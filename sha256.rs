// Initialize array of round constants.  (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

fn pad(data: &mut Vec<u8>) {
    let mut size: u64 = data.len() as u64;
    let mut zeroes = 64 - (size + 9 & 0x3F);
    if zeroes == 64 { zeroes = 0; }

    // Message length should be stored in bits.
    size *= 8;

    // Padding with 1 bit, then zeroes, and then message length bits.
    data.push(1 << 7);
    for _ in 0..zeroes { data.push(0u8); }
    for i in (0..8).rev() { data.push((size >> i * 8) as u8); }
}


fn rightrotate(w: u32, k: u8) -> u32 {
    w << 32 - k | w >> k
}

pub fn sha256(data: &mut Vec<u8>) -> [u32; 8] {
    // Initialize hash values.
    // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // `a to h` working variables from wiki pseudocode are stored in `wv`
    let mut wv: [u32; 8];

    // Create a 64-entry message schedule array w[0..63] of 32-bit words.
    let mut w: [u32; 64];

    pad(data);
    assert_eq!(data.len() % 64, 0);

    // Process the message in successive 512-bit chunks.
    for p in (0..data.len()).step_by(64) {
        // The initial values in w[0..63] don't matter, so many implementations zero them here.
        w = [0; 64];

        // Copy chunk into first 16 words w[0..15] of the message schedule array.
        for i in 0..16 {
            let base_index = p + (i << 2);

            // Creating a 32 bit word from 4 bytes
            w[i] = (data[base_index] as u32) << 24
                | (data[base_index + 1] as u32) << 16
                | (data[base_index + 2] as u32) << 8
                | (data[base_index + 3] as u32);
        }

        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array.
        for i in 16..64 {
            w[i] = (
                w[i - 16] as u64
                + (rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3)) as u64
                + w[i - 7] as u64
                + (rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10)) as u64
            ) as u32;
        }

        // Initialize working variables to current hash value.
        wv = h;

        // Compression function main loop.
        for i in 0..64 {
            let s1: u32 = rightrotate(wv[4], 6) ^ rightrotate(wv[4], 11) ^ rightrotate(wv[4], 25);
            let ch: u32 = (wv[4] & wv[5]) ^ (!wv[4] & wv[6]);
            let temp1: u32 = (wv[7] as u64 + s1 as u64 + ch as u64 + K[i] as u64 + w[i] as u64) as u32;
            let s0: u32 = rightrotate(wv[0], 2) ^ rightrotate(wv[0], 13) ^ rightrotate(wv[0], 22);
            let maj: u32 = (wv[0] & wv[1]) ^ (wv[0] & wv[2]) ^ (wv[1] & wv[2]);
            let temp2: u32 = (s0 as u64 + maj as u64) as u32;

            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = (wv[3] as u64 + temp1 as u64) as u32;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = (temp1 as u64 + temp2 as u64) as u32;
        }

        // Add the compressed chunk to the current hash value.
        for i in 0..8 {
            h[i] = (h[i] as u64 + wv[i] as u64) as u32;
        }
    }

    return h;
}

#[cfg(test)]
mod tests {
    use crate::sha256;

    #[test]
    fn basic() {
        let mut message: Vec<u8> = String::from("yo mama").into_bytes();
        // let mut message: Vec<u8> = vec![2, 3];
    
        let x = sha256(&mut message);
        assert_eq!(x, [3119063944, 2820444915, 3819283816, 977835619, 4181609796, 2419675891, 1024772233, 473324355]);
    }
}