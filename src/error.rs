//! Failures a caller can report.
//!
//! [`Error`] is a public non-exhaustive enum. A later command can add a
//! variant, and a match that needs to stay complete must include a wildcard.
//! The scan itself only branches through [`Error::is_not_found`]. Everything
//! else is printed.

use std::fmt;
use std::path::PathBuf;

/// A scan, config, or usage failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The command line is wrong. `message` is the usage text.
    Usage {
        /// What was wrong, and the form the command accepts.
        message: String,
    },
    /// A filesystem call failed.
    Io {
        /// Verb phrase, for example `stat` or `read directory`.
        operation: &'static str,
        /// Path the operation was aimed at.
        path: PathBuf,
        /// The system error.
        source: std::io::Error,
    },
    /// A config file or size flag could not be interpreted.
    Config {
        /// What to fix.
        message: String,
    },
}

/// Crate result.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Builds an I/O error that names the operation and the path.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::Error;
    ///
    /// let err = Error::io(
    ///     "stat",
    ///     "/missing",
    ///     std::io::Error::from(std::io::ErrorKind::NotFound),
    /// );
    /// assert!(err.is_not_found());
    /// ```
    pub fn io(operation: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    /// Reports whether the underlying system error is "not found".
    ///
    /// A missing cache is an empty scan, not a failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use disk_health::Error;
    ///
    /// let err = Error::io(
    ///     "stat",
    ///     "/missing",
    ///     std::io::Error::from(std::io::ErrorKind::NotFound),
    /// );
    /// assert!(err.is_not_found());
    /// ```
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage { message } | Self::Config { message } => f.write_str(message),
            Self::Io {
                operation, path, ..
            } => write!(f, "cannot {operation} {}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Usage { .. } | Self::Config { .. } => None,
        }
    }
}
