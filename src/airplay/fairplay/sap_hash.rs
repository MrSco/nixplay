// SPDX-License-Identifier: GPL-3.0-or-later
// Portions ported from doubletake (https://github.com/omarroth/doubletake), LGPL-3.0-or-later.

//! FairPlay's proprietary SAP hash. It is not a standard cryptographic hash.
//!
//! Porting note: the Go original relies on Go operator precedence (where `&`,
//! `&^`, `<<`, `>>`, `*`, `/` all bind tighter than `+`, `-`, `|`, `^`) and on
//! wrapping `byte` arithmetic. Every expression below is parenthesized
//! explicitly to reproduce Go's grouping, and every byte add/sub/mul/neg uses
//! the wrapping operations.

#[inline]
fn rotate_or_zero(input: u8, count: u8) -> u8 {
    if count == 0 {
        0
    } else {
        input.rotate_left((count & 7) as u32)
    }
}

#[inline]
fn wide_seed(input: u8, count: u8) -> u8 {
    if count == 0 {
        return SAP_SEED[0];
    }
    let input = input as u64;
    let left = if count < 64 { input << count } else { 0 };
    let right_shift = 8u8.wrapping_sub(count);
    let right = if right_shift < 64 { input >> right_shift } else { 0 };
    SAP_SEED[((left | right) % SAP_SEED.len() as u64) as usize]
}

#[inline]
fn majority(a: u8, b: u8, c: u8) -> u8 {
    a ^ ((a ^ b) & (a ^ c))
}

#[inline]
fn select_bits(mask: u8, if_set: u8, if_clear: u8) -> u8 {
    if_clear ^ ((if_set ^ if_clear) & mask)
}

#[inline]
fn square(value: u8) -> u8 {
    value.wrapping_mul(value)
}

#[inline]
fn cube(value: u8) -> u8 {
    value.wrapping_mul(value).wrapping_mul(value)
}

const INITIAL_HASH: [u8; 20] = [
    0x96, 0x5f, 0xc6, 0x53, 0xf8, 0x46, 0xcc, 0x18, 0xdf, 0xbe, //
    0xb2, 0xf8, 0x38, 0x62, 0xec, 0x22, 0x93, 0xd1, 0x20, 0x8f,
];

const INITIAL_MATRIX: [u8; 35] = [
    0x43, 0x54, 0x62, 0x7a, 0x18, 0xc3, 0xd6, 0xb3, 0x9a, 0x56, //
    0xf6, 0x1c, 0x14, 0x3f, 0x0c, 0x1d, 0x3b, 0x36, 0x83, 0xb1, //
    0x39, 0x51, 0x4a, 0xaa, 0x09, 0x3e, 0xfe, 0x44, 0xaf, 0xde, //
    0xc3, 0x20, 0x9d, 0x42, 0xb8,
];

const SAP_SEED: [u8; 21] = [
    0xed, 0x25, 0xd1, 0xbb, 0xbc, 0x27, 0x9f, 0x02, 0xa2, 0xa9, 0x11, //
    0x00, 0x0c, 0xb3, 0x52, 0xc0, 0xbd, 0xe3, 0x1b, 0x49, 0xc7,
];

struct SapState {
    hash: [u8; 20],
    matrix: [u8; 35],
    aux: [u8; 10],
    work: [u8; 210],
}

/// The FairPlay SAP hash of one 64-byte block.
pub(super) fn sap_hash(block: &[u8]) -> [u8; 16] {
    let block = &block[..64];
    let mut state = SapState {
        hash: INITIAL_HASH,
        matrix: INITIAL_MATRIX,
        aux: [0; 10],
        work: [0; 210],
    };

    // Load input in reversed four-byte groups.
    for (i, w) in state.work.iter_mut().enumerate() {
        *w = block[(i & 63) ^ 3];
    }

    // uint32 underflow changes the first of four scramble passes.
    {
        let work = &mut state.work;
        for i in 0u32..840 {
            let x = work[(i.wrapping_sub(155) % 210) as usize];
            let y = work[(i.wrapping_sub(57) % 210) as usize];
            let z = work[(i.wrapping_sub(13) % 210) as usize];
            let w = work[(i % 210) as usize];
            work[(i % 210) as usize] = y
                .rotate_left(5)
                .wrapping_add(z.rotate_left(3) ^ w)
                .wrapping_sub(x.rotate_left(7));
        }
    }

    state.nonlinear_circuit();

    let mut out = [0u8; 16];
    // Include terminal work XORs directly in their folded output lanes.
    out[..3].copy_from_slice(&state.aux[..3]);
    out[4..11].copy_from_slice(&state.aux[3..]);
    for v in out.iter_mut() {
        *v = v.wrapping_add(0xe1);
    }
    out[3] = 0x3d;
    out[11] = 0x3c;
    out[10] ^= state.aux[3] ^ 133;

    for (i, &value) in state.work.iter().enumerate() {
        let mut value = value;
        if i < state.matrix.len() {
            value ^= state.matrix[i];
        }
        if i < state.hash.len() {
            value ^= state.hash[i];
        }
        out[i & 15] ^= value;
    }

    // Reverse scramble.
    for i in 0usize..256 {
        out[i & 15] ^= out[(i.wrapping_sub(7)) & 15].rotate_left(1)
            ^ out[(i.wrapping_sub(5)) & 15].rotate_left(6)
            ^ out[(i.wrapping_sub(1)) & 15].rotate_left(5);
    }
    out
}

impl SapState {
    // Arithmetic wraps as bytes unless explicitly promoted before division or indexing.
    #[allow(clippy::cognitive_complexity)]
    fn nonlinear_circuit(&mut self) {
        let SapState {
            hash,
            matrix,
            aux,
            work,
        } = self;

        // h/m/s read hash/matrix/seed through work; ma reads matrix through aux.
        macro_rules! hi {
            ($i:expr) => {
                hash[(($i) as u8 % 20) as usize]
            };
        }
        macro_rules! si {
            ($i:expr) => {
                SAP_SEED[(($i) as u8 % 21) as usize]
            };
        }
        macro_rules! h {
            ($i:expr) => {
                hi!(work[$i])
            };
        }
        macro_rules! m {
            ($i:expr) => {
                matrix[(work[$i] % 35) as usize]
            };
        }
        macro_rules! s {
            ($i:expr) => {
                si!(work[$i])
            };
        }
        macro_rules! ma {
            ($i:expr) => {
                matrix[(aux[$i] % 35) as usize]
            };
        }

        matrix[12] = 0x14u8
            .wrapping_add(select_bits(92, work[64], work[99] / 3) & wide_seed(s!(206), 4));
        work[4] = 2u8.wrapping_mul(square(work[99] / 5));
        work[153] ^= square(m!(203)).wrapping_mul(work[190]);
        hash[3] = 0x13 ^ ((s!(205) >> 1) & 0x10);
        work[33] = work[33].wrapping_sub(s!(36) & !9u8);
        aux[5] = ((m!(67) & !2u8) | 1 | ((h!(181) >> 6) & 2) | (hash[3] & 0x10)).wrapping_sub(15);
        matrix[12] = 0x07;
        work[2] = work[2].wrapping_sub(64);
        hash[19] = s!(58);
        aux[4] = 92u8.wrapping_sub(m!(32));
        aux[9] = m!(15).wrapping_add(0x9e);
        work[34] = work[34].wrapping_add(si!(aux[9]) / 5);
        hash[19] = hash[19].wrapping_add(0xe6 ^ ((hi!(aux[9]) >> 1) & 0x66));
        work[15] ^= 3u8
            .wrapping_mul(rotate_or_zero(work[72], s!(190).wrapping_neg() & 7))
            .wrapping_sub(9u8.wrapping_mul(s!(126)));
        hash[15] ^= cube(m!(181));
        matrix[4] ^= work[202] / 3;
        matrix[1] = matrix[1].wrapping_add(cube(majority(
            92u8.wrapping_sub(hi!(aux[4])),
            !work[105],
            0xc6,
        )));
        hash[19] ^= ((224 | (s!(92) & 27)) as i32 * m!(41) as i32 / 3) as u8;
        work[140] = work[140].wrapping_add(rotate_or_zero(92, work[5].wrapping_neg() & 7));
        matrix[12] = matrix[12].wrapping_add(majority(!work[4] ^ m!(12), work[182], 192));
        work[36] = work[36].wrapping_add(125);
        work[124] = majority(majority(work[138], hash[15], 74), h!(43), 95).rotate_left(4);
        let aux_hash = hi!(aux[9]);
        aux[1] = 0x4c & !(aux_hash & (s!(68) << 1));
        aux[2] = 222u8.wrapping_sub(majority(
            ((work[177] as i32 + s!(79) as i32) >> 1) as u8,
            (3 * work[148] as i32 / 5) as u8,
            matrix[1],
        ));
        matrix[16] = matrix[16].wrapping_add(
            ((ma!(4) & !0x60u8) | aux_hash | 8).wrapping_sub(work[33].rotate_left(2) | 128),
        );
        hash[14] ^= ma!(2);
        work[19] = work[19].wrapping_add(majority(
            rotate_or_zero(si!(h!(201)), (m!(112) << 1) & 6),
            ((h!(208) & !0x7cu8) | (h!(164) & 0x7c)) / 5,
            37,
        ));
        matrix[8] = rotate_or_zero(140, square(s!(45)).wrapping_neg() & 7) ^ aux[4];
        work[190] = 56;
        work[53] = !((h!(83) | 204) / 5);
        hash[13] = hash[13].wrapping_add(h!(41));
        hash[10] = majority(ma!(4), work[2], aux[2]) / 15;
        aux[3] = 92u8.wrapping_sub(square(0x28 | (ma!(1) & (0x12 | (s!(2) & 4)))));
        let seed_bits = si!(aux[4]);
        matrix[13] ^= seed_bits;
        aux[6] = 92u8.wrapping_add(square(majority(m!(179).wrapping_sub(38), aux[2], 177)));
        let expansion_bits = majority(aux[3].wrapping_add(aux[4] & 74), !seed_bits, 121);
        work[47] ^= m!(89).wrapping_add(majority(expansion_bits ^ 0xa6, aux[4], 4));
        aux[7] = (seed_bits / 3)
            .wrapping_sub(ma!(9))
            .wrapping_sub(0x14 | (work[151] & ((aux[4] & 0x88) | 0x62)) | (aux[4] & 0x22));
        let expanded_selector = expansion_bits ^ ((aux[4] & 0xca) >> 1) ^ 75;
        aux[9] = aux[9].wrapping_add(
            0x80 | (majority(aux[7], work[151], 0x20) & 0x64) | (seed_bits & 0x44) | (ma!(9) & 0x1b),
        );
        matrix[33] ^= work[26];
        matrix[30] = ((aux[9] / 3).wrapping_sub((aux[4] & !8u8) | 0x13)) ^ h!(122);
        work[22] = (m!(90) & 0x1b) | 0x44;
        let mut wide = select_bits(
            71,
            matrix[(expanded_selector % 35) as usize],
            si!(aux[5]),
        ) as i64;
        matrix[18] = matrix[18].wrapping_add(((wide * wide * wide) >> 1) as u8);
        matrix[5] = matrix[5].wrapping_sub(s!(92));
        matrix[18] ^= select_bits(aux[3], ma!(3), select_bits(16, m!(183), work[41]))
            .wrapping_mul(select_bits(expanded_selector, h!(59), work[17]));
        matrix[22] = majority(
            select_bits(hash[14] | 28, (work[7] & 28) | 0x82, h!(93)),
            rotate_or_zero(
                ma!(4),
                rotate_or_zero(work[11], m!(28).wrapping_neg() & 7) & 7,
            ),
            matrix[33],
        )
        .wrapping_add(74);
        hash[15] = hash[15].wrapping_sub(majority(
            majority(aux[3], aux[4], 214),
            si!(h!(39) ^ 217),
            aux[6],
        ));

        let hash9 = hi!(aux[9]);
        let indexed_hash = hi!(((aux[4] / 3).wrapping_sub(aux[9] | work[22]))
            ^ aux[6]
            ^ (((m!(57) | hash9) & (0x52 | (aux[9] & 0x0d)))
                | (((m!(57) & hash9) | aux[9]) & 0x20)));
        aux[6] = square(square(h!(99))) | ma!(9);
        aux[1] = aux[1].wrapping_add(
            rotate_or_zero(h!(151) | s!(202), h!(50) & 7).wrapping_add(majority(
                h!(4),
                ((select_bits(matrix[16], indexed_hash, m!(138)) as i32
                    + select_bits(17, work[33], s!(39)) as i32)
                    / 5) as u8,
                147,
            )),
        );
        aux[0] = select_bits(
            hash[10] & 7,
            ma!(6) & h!(209),
            select_bits(
                0x47,
                rotate_or_zero(s!(127), ma!(6) & 7),
                si!(ma!(5)) << 1,
            ),
        );
        let selected_square = select_bits(198, square(m!(14)), h!(145) ^ aux[0]);
        let seed9 = si!(aux[9]);
        let hash3 = hi!(aux[3]);
        matrix[2] = matrix[2].wrapping_add(
            ((hash3 << 1) & ((work[25] & 0x96) | (seed9 & 8))) | (seed9 & 0x40),
        );
        matrix[14] =
            matrix[14].wrapping_sub(select_bits(34, work[97], ma!(3) & (aux[0] ^ m!(100))));
        work[23] ^= majority(majority(s!(17), hash3, aux[0]), work[50] / 3, 0x76) << 1;
        hash[17] = 115;
        hash[13] = ((majority(hi!(aux[7]), work[10], 82) >> 1) & 0x68) | (h!(39) & 0x17);
        matrix[33] = matrix[33].wrapping_sub(work[113] & 9);
        matrix[28] = matrix[28].wrapping_sub((aux[3] & !0x20u8) | ((work[110] >> 1) & 0x20));
        work[95] = si!(aux[3]);
        hash[15] = majority(work[95].wrapping_sub(48), !work[184], 189)
            & cube(majority(aux[7], si!(aux[1]), 0xaa));
        matrix[22] = matrix[22].wrapping_add(work[183]);
        aux[4] ^= 3u8.wrapping_mul(s!(1));
        aux[5] = aux[5].wrapping_add(
            198u8
                .wrapping_mul(majority(s!(178), ma!(1), 209))
                .wrapping_mul(h!(13))
                .wrapping_mul(s!(26) >> 1),
        );
        aux[8] = select_bits(10, ma!(3), ma!(9));
        matrix[18] =
            matrix[18].wrapping_sub(select_bits(hash[15], aux[5] / 15, cube(hi!(aux[6]) | 81)));
        aux[1] = aux[1].wrapping_add((si!(hi!(aux[1])) / 3).wrapping_sub(h!(160)));
        hash[16] = 147u8.wrapping_sub(majority(
            aux[0],
            majority(
                s!(69),
                work[172],
                aux[2].wrapping_sub(selected_square).wrapping_add(77),
            ),
            0xc2 | (aux[0] & 5),
        ));
        hash[3] = hash[3].wrapping_sub(wide_seed(
            majority(s!(155), work[105], 141),
            majority(s!(168), h!(29), 6) & 7,
        ));
        work[5] = rotate_or_zero(0x38, (h!(61) / 5).wrapping_neg() & 7) ^ ((!ma!(8)) / 5);
        work[198] = work[198].wrapping_add(work[3]);
        wide = (162 | ma!(9)) as i64;
        work[164] = work[164].wrapping_add((wide * wide / 5) as u8);
        aux[2] = majority(
            rotate_or_zero(139, aux[5].wrapping_neg() & 6),
            hi!(aux[3]),
            12,
        ) | select_bits(95, cube(seed9), hi!(aux[7]));
        matrix[12] = matrix[12]
            .wrapping_add((16 | ((work[103] | 60) & (aux[2] | (work[103] & 32)))) / 3);
        work[143] = work[143].wrapping_sub(
            0x12 | (select_bits(
                aux[9],
                select_bits(matrix[8], work[35], aux[7]),
                aux[8] / 3,
            ) & (0x4d | ((work[172] >> 1) & 0x20))),
        );
        matrix[29] = 162;
        hash[15] = hash[15].wrapping_add(majority(
            m!(149) ^ square(work[43]),
            select_bits(95, h!(125), si!(aux[1])) >> 1,
            115,
        ));
        aux[9] = aux[9].wrapping_sub(hi!(aux[7]));
        hash[7] = hash[7].wrapping_sub(square(rotate_or_zero(
            ma!(5),
            m!(17).wrapping_neg().wrapping_mul(m!(17) & 1),
        )));
        matrix[8] = matrix[8].wrapping_add(cube(s!(202)).wrapping_sub(work[184]));
        hash[16] = (m!(102) << 1) & 0x84;
        aux[6] ^= si!(aux[7]) >> 1;
        hash[7] = hash[7].wrapping_sub(h!(191).wrapping_sub(select_bits(
            177,
            si!(si!(aux[1])),
            s!(80) << 1,
        )));
        hash[6] = h!(119);
        hash[12] = (hi!(aux[8]) ^ m!(71).wrapping_add(m!(15)))
            & majority((work[118] & !0x2cu8) | 2, square(hi!(aux[9])), 27);
        let digest_index = select_bits(
            0xa9,
            s!(57).wrapping_mul(231),
            majority(work[32], ma!(1), 23),
        ) / 5;
        let seed_sample = si!(aux[6]);
        aux[5] = majority(
            (seed_sample & 0x1c) | (h!(82) & 0xa2) | (si!(digest_index) & 0x41),
            majority(cube(hi!(aux[7])), work[82], 92),
            192,
        ) ^ digest_index;
        matrix[25] ^= 2u8
            .wrapping_mul(hi!(aux[9]))
            .wrapping_mul(work[5])
            .wrapping_sub(rotate_or_zero(aux[4], seed_sample & 7) & aux[3].wrapping_add(110));
    }
}
