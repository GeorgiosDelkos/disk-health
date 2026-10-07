//! Raw mode, window size, and the two signals the UI watches.
//!
//! Unsafe is confined to the private `sys` module. The handlers store into an [`AtomicBool`]
//! and return. They do not allocate, lock, or run destructors, so they stay
//! async-signal-safe. `SA_RESTART` is left clear: a restarted `read` would
//! hide `SIGWINCH` from the UI thread.
//!
//! [`AtomicBool`]: std::sync::atomic::AtomicBool

use std::io;
use std::panic::PanicHookInfo;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// `sizeof(struct termios)` measured from the macOS SDK headers.
pub const TERMIOS_LEN: usize = 72;

const OFF_IFLAG: usize = 0;
const OFF_OFLAG: usize = 8;
const OFF_LFLAG: usize = 24;
const OFF_CC: usize = 32;
const VMIN: usize = 16;
const VTIME: usize = 17;

/// `termios.h`. Cleared so input is delivered a byte at a time.
const ICANON: u64 = 256;
const ECHO: u64 = 8;
/// Kept. Ctrl-C must still deliver `SIGINT` to the handler.
const ISIG: u64 = 128;
const IEXTEN: u64 = 1024;
const IXON: u64 = 512;
const ICRNL: u64 = 256;
const OPOST: u64 = 1;

const TCSANOW: i32 = 0;
const TCSAFLUSH: i32 = 2;

/// `signal.h`. Not set on the action we install.
const SA_RESTART: u32 = 2;
const SIGINT: i32 = 2;
const SIGWINCH: i32 = 28;

const ENTER_SCREEN: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[?2004l";
const LEAVE_SCREEN: &[u8] = b"\x1b[?25h\x1b[?1049l";

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static RESIZED: AtomicBool = AtomicBool::new(false);
type PanicHook = Box<dyn Fn(&PanicHookInfo<'_>) + Send + Sync>;

static PRIOR_HOOK: Mutex<Option<PanicHook>> = Mutex::new(None);

/// The flag [`crate::trash::apply`] polls between entries.
///
/// The `SIGINT` handler stores `true` with [`Ordering::Release`].
///
/// # Examples
///
/// ```
/// use disk_health::tty::interrupt_flag;
///
/// assert!(!interrupt_flag().load(std::sync::atomic::Ordering::Acquire));
/// ```
#[must_use]
pub fn interrupt_flag() -> &'static AtomicBool {
    &INTERRUPTED
}

/// Reports whether `SIGINT` has been delivered since the process started.
///
/// # Examples
///
/// ```
/// use disk_health::tty::interrupted;
///
/// let _ = interrupted();
/// ```
#[must_use]
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Acquire)
}

/// Reports a pending `SIGWINCH` and clears it.
///
/// # Examples
///
/// ```
/// use disk_health::tty::take_resized;
///
/// let _ = take_resized();
/// ```
#[must_use]
pub fn take_resized() -> bool {
    RESIZED.swap(false, Ordering::AcqRel)
}

/// Reports whether stdout is a terminal.
///
/// Cargo test captures stdout, so this is false under `cargo test` and the
/// default command does not draw the UI.
///
/// # Examples
///
/// ```
/// use disk_health::tty::stdout_is_tty;
///
/// let _ = stdout_is_tty();
/// ```
#[must_use]
pub fn stdout_is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}

/// Clears canonical input and echo. `ISIG` stays set.
///
/// `VMIN` is 0 and `VTIME` is 1 so `read` returns after a tenth of a second
/// and the UI can take findings off the scan channel.
///
/// # Examples
///
/// ```
/// use disk_health::tty::apply_raw_flags;
///
/// let mut termios = [0u8; 72];
/// termios[24] = 128; // ISIG in the low byte of c_lflag
/// apply_raw_flags(&mut termios);
/// assert_eq!(termios[24] & 128, 128);
/// assert_eq!(termios[32 + 16], 0);
/// assert_eq!(termios[32 + 17], 1);
/// ```
pub fn apply_raw_flags(termios: &mut [u8; TERMIOS_LEN]) {
    clear_flag(termios, OFF_LFLAG, ICANON | ECHO | IEXTEN);
    // A termios that arrived with `ISIG` clear would swallow Ctrl-C.
    set_flag(termios, OFF_LFLAG, ISIG);
    clear_flag(termios, OFF_IFLAG, IXON | ICRNL);
    clear_flag(termios, OFF_OFLAG, OPOST);
    termios[OFF_CC + VMIN] = 0;
    termios[OFF_CC + VTIME] = 1;
}

/// Owns the previous termios and the alternate screen.
///
/// Drop leaves the alternate screen and restores the termios captured at
/// [`Self::enter`]. A panic also restores, via [`PanicGuard`], because Drop
/// does not run if the process aborts inside the hook itself.
#[derive(Debug)]
pub struct RawMode {
    term_fd: i32,
    write_fd: i32,
    previous: [u8; TERMIOS_LEN],
}

impl RawMode {
    /// Puts `term_fd`'s terminal into raw mode and switches `write_fd` to
    /// the alternate screen.
    ///
    /// # Errors
    ///
    /// Returns an error when `term_fd` is not a terminal, or when `tcgetattr`,
    /// `tcsetattr`, or the screen write fails. A failed screen write puts the
    /// previous termios back.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::tty::RawMode;
    ///
    /// let _mode = RawMode::enter;
    /// ```
    pub fn enter(term_fd: i32, write_fd: i32) -> io::Result<Self> {
        if !sys::is_tty(term_fd) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "terminal is not a tty",
            ));
        }

        let previous = sys::read_termios(term_fd)?;
        let mut next = previous;
        apply_raw_flags(&mut next);
        sys::write_termios(term_fd, TCSAFLUSH, &next)?;

        if let Err(err) = sys::write_fd(write_fd, ENTER_SCREEN) {
            let _ = sys::write_termios(term_fd, TCSANOW, &previous);
            return Err(err);
        }

        Ok(Self {
            term_fd,
            write_fd,
            previous,
        })
    }

    /// The termios captured before raw mode, for the panic hook.
    #[must_use]
    pub fn previous(&self) -> [u8; TERMIOS_LEN] {
        self.previous
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = sys::write_fd(self.write_fd, LEAVE_SCREEN);
        let _ = sys::write_termios(self.term_fd, TCSANOW, &self.previous);
    }
}

/// Restores the terminal if a panic unwinds through the UI.
///
/// Drop puts the previous panic hook back. The hook itself restores termios
/// before calling that previous hook.
#[derive(Debug)]
pub struct PanicGuard {
    armed: bool,
}

impl PanicGuard {
    /// Installs the hook. `previous` is the termios from [`RawMode::previous`].
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::tty::PanicGuard;
    ///
    /// let _guard = PanicGuard::install;
    /// ```
    #[must_use]
    pub fn install(term_fd: i32, write_fd: i32, previous: [u8; TERMIOS_LEN]) -> Self {
        let old = std::panic::take_hook();
        *hook_slot() = Some(old);
        std::panic::set_hook(Box::new(move |info| {
            let _ = sys::write_fd(write_fd, LEAVE_SCREEN);
            let _ = sys::write_termios(term_fd, TCSANOW, &previous);
            if let Some(prior) = hook_slot().as_ref() {
                prior(info);
            }
        }));
        Self { armed: true }
    }
}

impl Drop for PanicGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(prior) = hook_slot().take()
        {
            std::panic::set_hook(prior);
        }
    }
}

/// Restores the previous `SIGINT` action, and `SIGWINCH` when it was installed.
#[derive(Debug)]
pub struct Signals {
    previous_int: [u8; sys::ACTION_LEN],
    previous_winch: Option<[u8; sys::ACTION_LEN]>,
}

impl Signals {
    /// Handles `SIGINT` by setting [`interrupt_flag`].
    ///
    /// # Errors
    ///
    /// Returns an error when `sigaction` fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::tty::Signals;
    ///
    /// let _install = Signals::install_interrupt;
    /// ```
    pub fn install_interrupt() -> io::Result<Self> {
        let previous_int = sys::install_signal(SIGINT, on_sigint)?;
        Ok(Self {
            previous_int,
            previous_winch: None,
        })
    }

    /// Handles `SIGINT` and `SIGWINCH`.
    ///
    /// # Errors
    ///
    /// Returns an error when `sigaction` fails. A failure on `SIGWINCH`
    /// restores the `SIGINT` action before returning.
    pub fn install_with_resize() -> io::Result<Self> {
        let mut signals = Self::install_interrupt()?;
        match sys::install_signal(SIGWINCH, on_winch) {
            Ok(previous) => signals.previous_winch = Some(previous),
            Err(err) => {
                let _ = sys::restore_signal(SIGINT, &signals.previous_int);
                return Err(err);
            }
        }
        Ok(signals)
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        let _ = sys::restore_signal(SIGINT, &self.previous_int);
        if let Some(previous) = &self.previous_winch {
            let _ = sys::restore_signal(SIGWINCH, previous);
        }
    }
}

/// Writes a frame. The caller converts `\n` to `\r\n` because `OPOST` is off.
///
/// # Errors
///
/// Returns an error when `write` fails.
pub fn write_frame(fd: i32, frame: &str) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(frame.len() + 3);
    bytes.extend_from_slice(b"\x1b[H");
    bytes.extend_from_slice(frame.as_bytes());
    sys::write_fd(fd, &bytes)
}

/// Reads one burst from `fd`. `Ok(None)` is a timeout (`VMIN` 0, `VTIME` 1).
///
/// # Errors
///
/// Returns an error when `read` fails for a reason other than interruption.
pub fn read_input(fd: i32) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 8];
    let read = sys::read_fd(fd, &mut buf)?;
    if read == 0 {
        Ok(None)
    } else {
        Ok(Some(buf[..read].to_vec()))
    }
}

/// Rows and columns from `TIOCGWINSZ`.
///
/// # Errors
///
/// Returns an error when `ioctl` fails.
pub fn window_size(fd: i32) -> io::Result<(u16, u16)> {
    sys::window_size(fd)
}

extern "C" fn on_sigint(_signal: i32) {
    INTERRUPTED.store(true, Ordering::Release);
}

extern "C" fn on_winch(_signal: i32) {
    RESIZED.store(true, Ordering::Release);
}

fn clear_flag(termios: &mut [u8; TERMIOS_LEN], offset: usize, bits: u64) {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&termios[offset..offset + 8]);
    let flags = u64::from_ne_bytes(bytes) & !bits;
    termios[offset..offset + 8].copy_from_slice(&flags.to_ne_bytes());
}

fn set_flag(termios: &mut [u8; TERMIOS_LEN], offset: usize, bits: u64) {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&termios[offset..offset + 8]);
    let flags = u64::from_ne_bytes(bytes) | bits;
    termios[offset..offset + 8].copy_from_slice(&flags.to_ne_bytes());
}

/// Clears `SA_RESTART`. A restarted `read` would hide `SIGWINCH`.
fn cleared_flags(flags: u32) -> u32 {
    flags & !SA_RESTART
}

fn hook_slot() -> std::sync::MutexGuard<'static, Option<PanicHook>> {
    PRIOR_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(target_os = "macos")]
mod sys {
    #![allow(
        unsafe_code,
        reason = "termios, ioctl, and sigaction from the system headers"
    )]

    use std::ffi::{c_int, c_ulong, c_void};
    use std::io;

    use super::TERMIOS_LEN;

    /// `sizeof(struct sigaction)` measured on this OS. `sa_mask` is at 8
    /// and `sa_flags` is at 12. The handler pointer is the first word.
    pub(super) const ACTION_LEN: usize = 16;

    const TIOCGWINSZ: c_ulong = 1_074_295_912;

    unsafe extern "C" {
        /// `int tcgetattr(int, struct termios *)` from `termios.h`.
        fn tcgetattr(fd: c_int, termios: *mut u8) -> c_int;
        /// `int tcsetattr(int, int, const struct termios *)` from `termios.h`.
        fn tcsetattr(fd: c_int, action: c_int, termios: *const u8) -> c_int;
        /// `int ioctl(int, unsigned long, ...)` from `sys/ioctl.h`.
        ///
        /// Declared with the one pointer argument `TIOCGWINSZ` takes
        /// (`struct winsize *` in `sys/ttycom.h`).
        fn ioctl(fd: c_int, request: c_ulong, arg: *mut u8) -> c_int;
        /// `int sigaction(int, const struct sigaction *, struct sigaction *)`
        /// from `signal.h`.
        fn sigaction(sig: c_int, action: *const u8, previous: *mut u8) -> c_int;
        /// `ssize_t write(int, const void *, size_t)` from `unistd.h`.
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        /// `ssize_t read(int, void *, size_t)` from `unistd.h`.
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        /// `int isatty(int)` from `unistd.h`.
        fn isatty(fd: c_int) -> c_int;
    }

    pub(super) fn read_termios(fd: i32) -> io::Result<[u8; TERMIOS_LEN]> {
        let mut buf = [0u8; TERMIOS_LEN];
        // SAFETY: `buf` is 72 bytes, the measured size of `struct termios`.
        // `tcgetattr` writes that struct and does not retain the pointer.
        // `fd` is a descriptor the caller still owns.
        let rc = unsafe { tcgetattr(fd, buf.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    pub(super) fn write_termios(
        fd: i32,
        action: i32,
        termios: &[u8; TERMIOS_LEN],
    ) -> io::Result<()> {
        // SAFETY: `termios` is 72 bytes, the measured size of `struct termios`.
        // `tcsetattr` reads it for the duration of the call. `action` is
        // `TCSANOW` or `TCSAFLUSH` from `termios.h`.
        let rc = unsafe { tcsetattr(fd, action, termios.as_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn window_size(fd: i32) -> io::Result<(u16, u16)> {
        let mut buf = [0u8; 8];
        // SAFETY: `TIOCGWINSZ` writes `struct winsize` (8 bytes: row, col,
        // xpixel, ypixel). `buf` is that size. The two `u16`s are copied
        // with `from_ne_bytes`, so the buffer's alignment does not matter.
        let rc = unsafe { ioctl(fd, TIOCGWINSZ, buf.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let rows = u16::from_ne_bytes([buf[0], buf[1]]);
        let cols = u16::from_ne_bytes([buf[2], buf[3]]);
        Ok((rows, cols))
    }

    pub(super) fn action_bytes(handler: extern "C" fn(c_int)) -> [u8; ACTION_LEN] {
        let mut bytes = [0u8; ACTION_LEN];
        let pointer = handler as usize;
        bytes[..8].copy_from_slice(&pointer.to_ne_bytes());

        // `sa_flags` is the word at offset 12. The mask drops `SA_RESTART`
        // if a later edit ORs it into that word before this line.
        let flags = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let flags = super::cleared_flags(flags);
        bytes[12..16].copy_from_slice(&flags.to_ne_bytes());
        bytes
    }

    pub(super) fn install_signal(
        signal: c_int,
        handler: extern "C" fn(c_int),
    ) -> io::Result<[u8; ACTION_LEN]> {
        let next = action_bytes(handler);
        let mut previous = [0u8; ACTION_LEN];
        // SAFETY: `next` and `previous` are 16 bytes, the measured size of
        // `struct sigaction` (`sa_mask` at 8, `sa_flags` at 12). The handler
        // only stores to an `AtomicBool`. Flags stay 0, so `SA_RESTART` is
        // not set. The kernel does not retain the pointers.
        let rc = unsafe { sigaction(signal, next.as_ptr(), previous.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(previous)
    }

    pub(super) fn restore_signal(signal: c_int, previous: &[u8; ACTION_LEN]) -> io::Result<()> {
        // SAFETY: `previous` was written by `sigaction` and is 16 bytes.
        // A null old-action pointer is how `sigaction` ignores the prior
        // value (`man sigaction`).
        let rc = unsafe { sigaction(signal, previous.as_ptr(), std::ptr::null_mut()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn write_fd(fd: i32, bytes: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let ptr = bytes[offset..].as_ptr().cast::<c_void>();
            let count = bytes.len() - offset;
            // SAFETY: `bytes` is a live slice. The pointer and length describe
            // the unread tail. `write` does not retain them. The cast matches
            // `const void *` in `unistd.h`.
            let rc = unsafe { write(fd, ptr, count) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let wrote = usize::try_from(rc).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "write returned a negative count",
                )
            })?;
            if wrote == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
            }
            offset += wrote;
        }
        Ok(())
    }

    pub(super) fn read_fd(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let ptr = buf.as_mut_ptr().cast::<c_void>();
            // SAFETY: `buf` is a live mutable slice. `read` writes at most
            // `buf.len()` bytes and does not retain the pointer. The cast
            // matches `void *` in `unistd.h`.
            let rc = unsafe { read(fd, ptr, buf.len()) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return usize::try_from(rc).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "read returned a negative count")
            });
        }
    }

    pub(super) fn is_tty(fd: i32) -> bool {
        // SAFETY: `isatty` only inspects the descriptor type (`unistd.h`).
        unsafe { isatty(fd) == 1 }
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    use std::io;

    use super::TERMIOS_LEN;

    pub(super) const ACTION_LEN: usize = 16;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "disk-health runs on macOS")
    }

    pub(super) fn read_termios(_fd: i32) -> io::Result<[u8; TERMIOS_LEN]> {
        Err(unsupported())
    }

    pub(super) fn write_termios(
        _fd: i32,
        _action: i32,
        _termios: &[u8; TERMIOS_LEN],
    ) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn window_size(_fd: i32) -> io::Result<(u16, u16)> {
        Err(unsupported())
    }

    pub(super) fn action_bytes(_handler: extern "C" fn(i32)) -> [u8; ACTION_LEN] {
        let mut bytes = [0; ACTION_LEN];
        let flags = super::cleared_flags(0);
        bytes[12..16].copy_from_slice(&flags.to_ne_bytes());
        bytes
    }

    pub(super) fn install_signal(
        _signal: i32,
        _handler: extern "C" fn(i32),
    ) -> io::Result<[u8; ACTION_LEN]> {
        Err(unsupported())
    }

    pub(super) fn restore_signal(_signal: i32, _previous: &[u8; ACTION_LEN]) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn write_fd(_fd: i32, _bytes: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn read_fd(_fd: i32, _buf: &mut [u8]) -> io::Result<usize> {
        Err(unsupported())
    }

    pub(super) fn is_tty(_fd: i32) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn raw_flags_keep_isig_and_poll() {
        let mut termios = [0u8; TERMIOS_LEN];
        // `ISIG` starts clear. `apply_raw_flags` has to set it.
        let lflag = ICANON | ECHO | IEXTEN;
        termios[OFF_LFLAG..OFF_LFLAG + 8].copy_from_slice(&lflag.to_ne_bytes());
        termios[OFF_IFLAG..OFF_IFLAG + 8].copy_from_slice(&(IXON | ICRNL).to_ne_bytes());
        termios[OFF_OFLAG..OFF_OFLAG + 8].copy_from_slice(&OPOST.to_ne_bytes());

        apply_raw_flags(&mut termios);

        let lflag = u64::from_ne_bytes(termios[OFF_LFLAG..OFF_LFLAG + 8].try_into().unwrap());
        let iflag = u64::from_ne_bytes(termios[OFF_IFLAG..OFF_IFLAG + 8].try_into().unwrap());
        let oflag = u64::from_ne_bytes(termios[OFF_OFLAG..OFF_OFLAG + 8].try_into().unwrap());
        assert_eq!(lflag & ISIG, ISIG);
        assert_eq!(lflag & (ICANON | ECHO | IEXTEN), 0);
        assert_eq!(iflag & (IXON | ICRNL), 0);
        assert_eq!(oflag & OPOST, 0);
        assert_eq!(termios[OFF_CC + VMIN], 0);
        assert_eq!(termios[OFF_CC + VTIME], 1);
    }

    #[test]
    fn signal_action_does_not_set_sa_restart() {
        let bytes = sys::action_bytes(on_sigint);
        let flags = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());
        let mask = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(flags & SA_RESTART, 0);
        assert_eq!(mask, 0);
        assert_ne!(usize::from_ne_bytes(bytes[..8].try_into().unwrap()), 0);
    }

    #[test]
    fn handlers_only_set_their_flag() {
        INTERRUPTED.store(false, Ordering::Release);
        RESIZED.store(false, Ordering::Release);
        on_sigint(SIGINT);
        assert!(INTERRUPTED.load(Ordering::Acquire));
        assert!(!RESIZED.load(Ordering::Acquire));
        on_winch(SIGWINCH);
        assert!(RESIZED.load(Ordering::Acquire));
        let _ = take_resized();
        assert!(!take_resized());
    }

    #[test]
    fn raw_mode_restores_termios_when_the_tty_opens() {
        use std::os::fd::AsRawFd;

        let Ok(file) = std::fs::File::open("/dev/tty") else {
            return;
        };
        let fd = file.as_raw_fd();
        if !sys::is_tty(fd) {
            return;
        }
        let before = sys::read_termios(fd).expect("tcgetattr");
        let mode = RawMode::enter(fd, fd).expect("raw mode");
        drop(mode);
        let after = sys::read_termios(fd).expect("tcgetattr after drop");
        assert_eq!(before, after);
    }

    #[test]
    fn enter_refuses_a_regular_file() {
        use std::os::fd::AsRawFd;

        let path = std::env::temp_dir().join(format!("disk-health-tty-{}", std::process::id()));
        std::fs::write(&path, b"not a tty").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let err = RawMode::enter(file.as_raw_fd(), file.as_raw_fd()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        drop(file);
        std::fs::remove_file(&path).unwrap();
    }
}
