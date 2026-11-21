// SPDX-License-Identifier: GPL-3.0-or-later
// Portions ported from doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! FairPlay's mutated MD5 compression function.
//!
//! FairPlay uses the standard MD5 compression rounds and constants, but reads
//! message words as big endian and mutates the message schedule after round 31.
//! Those differences mean a stock MD5 implementation cannot be used here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mutation {
    /// Used by the FPSAP mask/digest derivations.
    Swap,
    /// Used by the FPSAP descriptor (session MAC key) derivation.
    Cycle,
    /// Used by the FairPlay key-wrapping KDF.
    Kdf,
}

const SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const CONSTANT: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, //
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, //
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, //
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, //
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, //
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, //
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, //
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, //
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, //
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, //
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, //
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, //
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, //
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, //
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, //
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// One FairPlay MD5 compression of a 64-byte block. Message words are read
/// big endian; the schedule is mutated after round 31 according to `mutation`.
pub(super) fn compress(state: [u32; 4], block: &[u8], mutation: Mutation) -> [u32; 4] {
    let block = &block[..64];
    let mut message = [0u32; 16];
    for (i, word) in message.iter_mut().enumerate() {
        *word = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let [mut a, mut b, mut c, mut d] = state;
    for round in 0..64 {
        let (f, word) = if round < 16 {
            ((b & c) | (!b & d), round)
        } else if round < 32 {
            ((d & b) | (!d & c), (5 * round + 1) & 15)
        } else if round < 48 {
            (b ^ c ^ d, (3 * round + 5) & 15)
        } else {
            (c ^ (b | !d), (7 * round) & 15)
        };

        let rotated = a
            .wrapping_add(f)
            .wrapping_add(CONSTANT[round])
            .wrapping_add(message[word])
            .rotate_left(SHIFT[round]);
        let new_b = b.wrapping_add(rotated);
        a = d;
        d = c;
        c = b;
        b = new_b;

        if round == 31 {
            mutate_message(&mut message, a, b, c, d, mutation);
        }
    }

    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
    ]
}

fn mutate_message(message: &mut [u32; 16], a: u32, b: u32, c: u32, d: u32, mutation: Mutation) {
    let nibble = |v: u32, shift: u32| ((v >> shift) & 15) as usize;
    match mutation {
        Mutation::Swap => {
            let indices = [
                nibble(a, 0),
                nibble(b, 0),
                nibble(c, 0),
                nibble(d, 0),
                nibble(a, 4),
                nibble(b, 4),
                nibble(c, 4),
                nibble(d, 4),
            ];
            for (i, &j) in indices.iter().enumerate() {
                message.swap(i, j);
            }
        }
        Mutation::Cycle => {
            let indices = [
                nibble(a, 0),
                nibble(b, 0),
                nibble(c, 0),
                nibble(d, 0),
                nibble(a, 4),
                nibble(b, 4),
                nibble(c, 4),
                nibble(d, 4),
            ];
            let first = message[indices[0]];
            for i in 0..indices.len() - 1 {
                message[indices[i]] = message[indices[i + 1]];
            }
            message[indices[indices.len() - 1]] = first;
        }
        Mutation::Kdf => {
            message.swap(nibble(a, 0), nibble(b, 0));
            message.swap(nibble(c, 0), nibble(d, 0));
            for shift in [4, 8, 12] {
                message.swap(nibble(a, shift), nibble(b, shift));
            }
        }
    }
}

/// Interpret 16 bytes as four little-endian words.
pub(super) fn words_from_le(input: &[u8; 16]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (i, word) in out.iter_mut().enumerate() {
        *word = u32::from_le_bytes(input[i * 4..i * 4 + 4].try_into().unwrap());
    }
    out
}

/// Serialize four words big endian.
pub(super) fn words_to_be(words: [u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, word) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
