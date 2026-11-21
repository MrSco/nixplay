/// Pure-Rust Apple Lossless (ALAC) encoder using spec-compliant verbatim (uncompressed) framing.
///
/// AirPlay 2 and AirPlay 1 (RAOP) standard real-time streams use:
/// - 44100 Hz, 16-bit signed stereo
/// - 352 stereo frames per packet (spf = 352)
///
/// An uncompressed ALAC stereo (CPE) packet for 352 frames is 1416 bytes,
/// fitting cleanly inside a single 1500-byte Ethernet MTU UDP datagram even with
/// the 12-byte RTP header + 24-byte AirPlay 2 ChaCha20-Poly1305 tag & nonce.

pub const SAMPLES_PER_FRAME: usize = 352;
pub const SAMPLE_RATE: u32 = 44100;

struct BitWriter {
    buf: Vec<u8>,
    cur: u8,
    bits_used: u8,
}

impl BitWriter {
    fn with_capacity(bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(bytes),
            cur: 0,
            bits_used: 0,
        }
    }

    #[inline]
    fn write_bits(&mut self, value: u32, count: u8) {
        let mut remaining = count;
        while remaining > 0 {
            let space = 8 - self.bits_used;
            let take = remaining.min(space);
            let shift = remaining - take;
            let mask = if take == 32 { u32::MAX } else { (1u32 << take) - 1 };
            let bits = ((value >> shift) & mask) as u8;
            self.cur = if take == 8 { bits } else { (self.cur << take) | bits };
            self.bits_used += take;
            remaining -= take;
            if self.bits_used == 8 {
                self.buf.push(self.cur);
                self.cur = 0;
                self.bits_used = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_used > 0 {
            self.cur <<= 8 - self.bits_used;
            self.buf.push(self.cur);
        }
        self.buf
    }
}

/// Encode interleaved little-endian 16-bit stereo PCM samples (`[L0, R0, L1, R1, ...]`)
/// into an ALAC Channel Pair Element (CPE) verbatim frame.
///
/// `pcm_le` length must be a multiple of 4 bytes (2 channels * 2 bytes/sample).
pub fn encode_alac_verbatim_stereo_16(pcm_le: &[u8]) -> Vec<u8> {
    let num_frames = pcm_le.len() / 4;
    let mut bw = BitWriter::with_capacity(16 + pcm_le.len());

    // ID_CPE (Channel Pair Element) = 1 (3 bits)
    bw.write_bits(1, 3);
    // element_instance_tag = 0 (4 bits)
    bw.write_bits(0, 4);
    // 12 unused header bits
    bw.write_bits(0, 12);
    // hasSize = 1 (1 bit) -> explicit 32-bit frame length follows
    bw.write_bits(1, 1);
    // unused/extraBytes = 0 (2 bits)
    bw.write_bits(0, 2);
    // isNotCompressed (verbatim escape flag) = 1 (1 bit)
    bw.write_bits(1, 1);
    // outputSamples (32 bits big-endian)
    bw.write_bits(num_frames as u32, 32);

    // Interleaved big-endian 16-bit signed stereo samples
    for chunk in pcm_le.chunks_exact(4) {
        let l = i16::from_le_bytes([chunk[0], chunk[1]]) as u16;
        let r = i16::from_le_bytes([chunk[2], chunk[3]]) as u16;
        bw.write_bits(l as u32, 16);
        bw.write_bits(r as u32, 16);
    }

    // ID_END = 7 (3 bits)
    bw.write_bits(7, 3);

    bw.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_352_frame_header_and_size() {
        let pcm = vec![0u8; SAMPLES_PER_FRAME * 4];
        let alac = encode_alac_verbatim_stereo_16(&pcm);
        // 3+4+12+1+2+1+32 + 352*32 + 3 = 11322 bits = 1415.25 -> 1416 bytes
        assert_eq!(alac.len(), 1416);
        // First 3 bytes: 001_0000_0 | 0000_0000 | 000_1_00_1_0 = 0x20, 0x00, 0x12
        assert_eq!(alac[0], 0x20);
        assert_eq!(alac[1], 0x00);
        assert_eq!(alac[2], 0x12);
        // Check trailing ID_END = 111 at bits 11319..11322 (last byte top 2 bits after byte boundary)
        // 11319 bits = 1414 bytes + 7 bits -> bit 7 of byte 1414 is 1, bits 0..2 of byte 1415 are 11
        assert_eq!(alac[1414] & 0x01, 0x01);
        assert_eq!(alac[1415] & 0xC0, 0xC0);
    }
}
