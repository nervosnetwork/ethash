extern "C" {
    /// Hashes input. Returns -1 if either out or input does not exist. Otherwise returns 0.
    pub fn keccak_256(out: *mut u8, outlen: usize, input: *const u8, inputlen: usize) -> i32;
    /// Hashes input. Returns -1 if either out or input does not exist. Otherwise returns 0.
    pub fn keccak_512(out: *mut u8, outlen: usize, input: *const u8, inputlen: usize) -> i32;
}

pub mod keccak {
    pub use super::{keccak_256 as raw_keccak_256, keccak_512 as raw_keccak_512};

    pub fn keccak_512(input: &[u8], output: &mut [u8]) {
        unsafe {
            raw_keccak_512(
                output.as_mut_ptr(),
                output.len(),
                input.as_ptr(),
                input.len(),
            )
        };
    }

    pub fn keccak_512_replace(input: &mut [u8]) {
        unsafe { raw_keccak_512(input.as_mut_ptr(), input.len(), input.as_ptr(), input.len()) };
    }

    pub fn keccak_256(input: &[u8], output: &mut [u8]) {
        unsafe {
            raw_keccak_256(
                output.as_mut_ptr(),
                output.len(),
                input.as_ptr(),
                input.len(),
            )
        };
    }

    pub fn keccak_256_replace(input: &mut [u8]) {
        unsafe { raw_keccak_256(input.as_mut_ptr(), input.len(), input.as_ptr(), input.len()) };
    }
}
