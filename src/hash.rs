//! SHA-256 for plan ids and action ids.
//!
//! FIPS 180-4, with the initial hash and the round constants inlined. A crate
//! would be the usual way to get this, and this binary has none. Inputs are
//! plan files and log lines, so a streaming API is not worth the extra state.

/// Digest of `message`.
///
/// # Panics
///
/// Panics if the bit length of `message` does not fit in a `u64`. A plan file
/// cannot reach that size.
///
/// # Examples
///
/// ```
/// use disk_health::hash::{sha256, to_hex};
///
/// assert_eq!(
///     to_hex(&sha256(b"")),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// ```
#[must_use]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut state = INITIAL;
    let mut offset = 0;
    while offset + BLOCK <= message.len() {
        let mut block = [0; BLOCK];
        block.copy_from_slice(&message[offset..offset + BLOCK]);
        compress(&mut state, &block);
        offset += BLOCK;
    }

    let mut block = [0; BLOCK];
    let rest = &message[offset..];
    block[..rest.len()].copy_from_slice(rest);
    block[rest.len()] = 0x80;
    if rest.len() >= LENGTH_AT {
        compress(&mut state, &block);
        block = [0; BLOCK];
    }

    let bytes = u64::try_from(message.len()).expect("sha256 input length fits in u64");
    let bits = bytes.checked_mul(8).expect("sha256 bit length fits in u64");
    block[LENGTH_AT..].copy_from_slice(&bits.to_be_bytes());
    compress(&mut state, &block);

    let mut out = [0; 32];
    for (index, word) in state.iter().enumerate() {
        let start = index * 4;
        out[start..start + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Lowercase hex, two characters per byte.
///
/// # Examples
///
/// ```
/// use disk_health::hash::to_hex;
///
/// assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
/// ```
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

const BLOCK: usize = 64;
const LENGTH_AT: usize = 56;

const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn compress(state: &mut [u32; 8], block: &[u8; BLOCK]) {
    let mut word = [0; 64];
    for (index, slot) in word.iter_mut().enumerate().take(16) {
        let start = index * 4;
        let bytes = [
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ];
        *slot = u32::from_be_bytes(bytes);
    }
    for index in 16..64 {
        let small = small_sigma(word[index - 15], 7, 18, 3);
        let large = small_sigma(word[index - 2], 17, 19, 10);
        word[index] = word[index - 16]
            .wrapping_add(small)
            .wrapping_add(word[index - 7])
            .wrapping_add(large);
    }

    let mut letter = *state;
    for index in 0..64 {
        let upper = big_sigma(letter[4], 6, 11, 25);
        let choose = (letter[4] & letter[5]) ^ (!letter[4] & letter[6]);
        let first = letter[7]
            .wrapping_add(upper)
            .wrapping_add(choose)
            .wrapping_add(ROUND[index])
            .wrapping_add(word[index]);
        let lower = big_sigma(letter[0], 2, 13, 22);
        let majority = (letter[0] & letter[1]) ^ (letter[0] & letter[2]) ^ (letter[1] & letter[2]);
        let second = lower.wrapping_add(majority);

        letter[7] = letter[6];
        letter[6] = letter[5];
        letter[5] = letter[4];
        letter[4] = letter[3].wrapping_add(first);
        letter[3] = letter[2];
        letter[2] = letter[1];
        letter[1] = letter[0];
        letter[0] = first.wrapping_add(second);
    }

    for index in 0..8 {
        state[index] = state[index].wrapping_add(letter[index]);
    }
}

fn small_sigma(value: u32, first: u32, second: u32, shift: u32) -> u32 {
    value.rotate_right(first) ^ value.rotate_right(second) ^ (value >> shift)
}

fn big_sigma(value: u32, first: u32, second: u32, third: u32) -> u32 {
    value.rotate_right(first) ^ value.rotate_right(second) ^ value.rotate_right(third)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_short_vectors() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
