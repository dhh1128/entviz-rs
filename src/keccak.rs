//! Minimal pure-Rust Keccak-256 (the original Keccak, NOT NIST SHA3-256).
//!
//! EIP-55 Ethereum address checksums use Keccak-256, which uses the original
//! Keccak padding (`0x01` … `0x80`). NIST SHA3-256 uses a different padding
//! (`0x06` … `0x80`) and produces a different digest, so it cannot be used
//! here. Faithful port of the reference `src/entviz/keccak.py`.

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Rho rotation offsets, indexed _ROT[y][x].
const ROT: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

#[inline]
fn rotl64(x: u64, n: u32) -> u64 {
    x.rotate_left(n & 63)
}

fn keccak_f1600(state: &mut [[u64; 5]; 5]) {
    for &rc in RC.iter() {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] ^= d[x];
            }
        }

        // Rho + Pi
        let mut b = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = rotl64(state[x][y], ROT[y][x]);
            }
        }

        // Chi
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
            }
        }

        // Iota
        state[0][0] ^= rc;
    }
}

fn absorb_block(state: &mut [[u64; 5]; 5], block: &[u8]) {
    for (i, &byte) in block.iter().enumerate() {
        let lane_index = i / 8;
        let x = lane_index % 5;
        let y = lane_index / 5;
        let byte_in_lane = i % 8;
        state[x][y] ^= (byte as u64) << (8 * byte_in_lane);
    }
}

/// Return the 32-byte Keccak-256 digest of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [[0u64; 5]; 5];

    let mut offset = 0;
    let n = data.len();
    while n - offset >= RATE {
        absorb_block(&mut state, &data[offset..offset + RATE]);
        keccak_f1600(&mut state);
        offset += RATE;
    }

    // Final block: 0x01 … 0x80 padding.
    let mut last = data[offset..].to_vec();
    last.push(0x01);
    while last.len() < RATE {
        last.push(0x00);
    }
    *last.last_mut().unwrap() |= 0x80;
    absorb_block(&mut state, &last);
    keccak_f1600(&mut state);

    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let lane_index = i / 8;
        let x = lane_index % 5;
        let y = lane_index / 5;
        let byte_in_lane = i % 8;
        *o = ((state[x][y] >> (8 * byte_in_lane)) & 0xFF) as u8;
    }
    out
}

/// Hex (lowercase) of the Keccak-256 digest.
pub fn keccak256_hex(data: &[u8]) -> String {
    keccak256(data).iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_vector() {
        // Cross-checked against the Python reference.
        assert_eq!(
            keccak256_hex(b"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "d385650ce8fdc6db7ee3a091d34814dbc4ce18219ffae52182efff4034d707e5"
        );
    }

    #[test]
    fn empty() {
        // Keccak-256("") known answer.
        assert_eq!(
            keccak256_hex(b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
