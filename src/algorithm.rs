#![allow(dead_code)]
#![cfg_attr(feature = "cargo-clippy", allow(many_single_char_names))]

use bigint::{H256, H512};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use keccak::keccak::{
    keccak_256, keccak_256_replace, keccak_512_replace, raw_keccak_256, raw_keccak_512,
};
use primal::is_prime;
use rayon::prelude::*;
use shared::{Epoch, CACHE_SIZES, DATA_SET_SIZES, MAX_EPOCH};
use std::ptr::Unique;

pub const REVISION: u32 = 23;
pub const WORD_BYTES: usize = 4;
pub const DATASET_BYTES_INIT: u64 = 1 << 30;
pub const DATASET_BYTES_GROWTH: u64 = 1 << 23;
pub const CACHE_BYTES_INIT: u64 = 1 << 24;
pub const CACHE_BYTES_GROWTH: u64 = 1 << 17;
pub const CACHE_MULTIPLIER: u64 = 1024;
pub const EPOCH_LENGTH: u64 = 30_000;
pub const MIX_BYTES: usize = 128;
pub const HASH_BYTES: usize = 64;
pub const DATASET_PARENTS: usize = 256;
pub const CACHE_ROUNDS: u64 = 3;
pub const ACCESSES: usize = 64;
pub const FNV_PRIME: u32 = 0x0100_0193;
pub const MIX_HASHES: usize = MIX_BYTES / HASH_BYTES;

pub fn get_epoch(block_height: u64) -> Epoch {
    block_height / EPOCH_LENGTH
}

pub fn get_cache_size(epoch: Epoch) -> usize {
    if epoch < MAX_EPOCH {
        return CACHE_SIZES[epoch as usize];
    }
    let mut sz = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * epoch - HASH_BYTES as u64;
    while !is_prime(sz / HASH_BYTES as u64) {
        sz -= 2 * HASH_BYTES as u64;
    }
    sz as usize
}

pub fn get_dataset_size(epoch: Epoch) -> usize {
    if epoch < MAX_EPOCH {
        return DATA_SET_SIZES[epoch as usize];
    }
    let mut sz = DATASET_BYTES_INIT + DATASET_BYTES_GROWTH * epoch - MIX_BYTES as u64;
    while !is_prime(sz / MIX_BYTES as u64) {
        sz -= 2 * MIX_BYTES as u64;
    }
    sz as usize
}

pub fn seed_hash(epoch: Epoch) -> H256 {
    let mut seed = [0u8; 32];
    for _ in 0..epoch {
        keccak_256_replace(&mut seed);
    }
    H256(seed)
}

unsafe fn initialize_cache(cache: &mut [u8], num: usize, seed: &H256) {
    let ptr: *mut u8 = cache.as_mut_ptr();
    debug_assert!(seed.len() == 32);
    raw_keccak_512(ptr, HASH_BYTES, seed.as_ptr(), seed.len());

    for i in 1..num {
        let dst = ptr.offset((i * HASH_BYTES) as isize);
        let src = ptr.offset(((i - 1) * HASH_BYTES) as isize);

        raw_keccak_512(dst, HASH_BYTES, src, HASH_BYTES);
    }
}

/// recover boundary from mix hash. use to cheap check
pub fn recover_boundary(pow_hash: &H256, nonce: u64, mix_hash: &H256) -> H256 {
    unsafe {
        let mut buf: [u8; 64 + 32] = ::std::mem::uninitialized();

        ::std::ptr::copy_nonoverlapping(pow_hash.as_ptr(), buf.as_mut_ptr(), 32);
        ::std::ptr::copy_nonoverlapping(
            &nonce as *const u64 as *const u8,
            buf[32..].as_mut_ptr(),
            8,
        );

        raw_keccak_512(buf.as_mut_ptr(), 64, buf.as_ptr(), 40);
        ::std::ptr::copy_nonoverlapping(mix_hash.as_ptr(), buf[64..].as_mut_ptr(), 32);

        let mut ret: [u8; 32] = ::std::mem::uninitialized();
        raw_keccak_256(ret.as_mut_ptr(), ret.len(), buf.as_ptr(), buf.len());

        H256(ret)
    }
}

pub fn calc_cache(cache: &mut [u8], num: usize, seed: &H256) {
    unsafe {
        initialize_cache(cache, num, seed);
    }

    for _ in 0..CACHE_ROUNDS {
        for i in 0..num {
            let idx = i * HASH_BYTES;
            //read word
            let v = ((&cache[idx..]).read_u32::<LittleEndian>().unwrap() as usize) % num;
            let src_idx = (num + i - 1) % num * HASH_BYTES;

            // word xor
            let mut temp = [0u8; 64];
            unroll! {
                for w in 0..8 {
                    (&mut temp[(w * 8) ..]).write_u64::<LittleEndian>(
                        (&cache[(src_idx + (w * 8))..]).read_u64::<LittleEndian>().unwrap() ^
                        (&cache[((v * HASH_BYTES) + (w * 8))..]).read_u64::<LittleEndian>().unwrap()
                    ).expect("write_u64");
                }
            }

            unsafe {
                let ptr: *mut u8 = cache.as_mut_ptr();
                let dst = ptr.offset((i * HASH_BYTES) as isize);
                raw_keccak_512(dst, HASH_BYTES, temp.as_ptr(), HASH_BYTES);
            }
        }
    }
}

pub fn generate_cache(cache_size: usize, seed: &H256) -> Vec<u8> {
    debug_assert!(cache_size % HASH_BYTES as usize == 0);

    let mut cache = Vec::with_capacity(cache_size);
    cache.resize(cache_size, 0);
    let num = cache.len() / HASH_BYTES as usize;

    calc_cache(&mut cache, num, seed);
    cache
}

fn fnv(x: u32, y: u32) -> u32 {
    (x.wrapping_mul(FNV_PRIME) ^ y)
}

fn fnv64(a: &mut [u8; 64], b: [u8; 64]) {
    unroll! {
        for i in 0..16 {
            let j = i * 4;
            let a32 = (&a[j..]).read_u32::<LittleEndian>().expect("read_u32");
            let b32 = (&b[j..]).read_u32::<LittleEndian>().expect("read_u32");

            (&mut a[j..]).write_u32::<LittleEndian>(fnv(
                a32,
                b32,
            )).expect("write_u32");
        }
    }
}

fn fnv128(a: &mut [u8; 128], b: [u8; 128]) {
    unroll! {
        for i in 0..32 {
            let j = i * 4;
            let a32 = (&a[j..]).read_u32::<LittleEndian>().expect("read_u32");
            let b32 = (&b[j..]).read_u32::<LittleEndian>().expect("read_u32");

            (&mut a[j..]).write_u32::<LittleEndian>(fnv(
                a32,
                b32,
            )).expect("write_u32");
        }
    }
}

fn calc_dataset_item(cache: &[u8], index: usize) -> H512 {
    debug_assert!(cache.len() % 64 == 0);

    let n = cache.len() / HASH_BYTES;
    let r = HASH_BYTES / WORD_BYTES;

    let mut mix = [0u8; 64];
    let mix_idx = index % n * 64;
    mix[..].copy_from_slice(&cache[mix_idx..mix_idx + HASH_BYTES]);

    // mix0 ^= index
    let mix0 = { mix.as_ref().read_u32::<LittleEndian>().unwrap() ^ index as u32 };
    mix.as_mut()
        .write_u32::<LittleEndian>(mix0)
        .expect("write_u32");

    keccak_512_replace(&mut mix);

    for j in 0..DATASET_PARENTS {
        let cache_index = fnv(
            (index ^ j) as u32,
            (&mix[(j % r * WORD_BYTES)..])
                .read_u32::<LittleEndian>()
                .expect("write_u32"),
        ) as usize % n * HASH_BYTES;
        let mut item = [0u8; 64];
        item[..].copy_from_slice(&cache[cache_index..cache_index + HASH_BYTES]);
        fnv64(&mut mix, item);
    }
    keccak_512_replace(&mut mix);
    H512(mix)
}

// use `Unique` wrap make ptr `Sync`
pub fn calc_dataset(dataset: &mut [u8], num: usize, cache: &[u8]) {
    let ptr: *mut u8 = dataset.as_mut_ptr();

    let shared_ptr = Unique::new(ptr).expect("Unique ptr");
    (0..num).into_par_iter().for_each(|i| {
        let item = calc_dataset_item(cache, i);
        unsafe {
            let ptr = shared_ptr.as_ptr();
            let dst = ptr.offset((i * HASH_BYTES) as isize);
            ::std::ptr::copy_nonoverlapping(item.as_ptr(), dst, item.len());
        }
    });
}

pub fn generate_dataset(full_size: usize, cache: &[u8]) -> Vec<u8> {
    let num = full_size / HASH_BYTES as usize;
    let mut dataset = Vec::with_capacity(full_size);
    dataset.resize(full_size, 0);
    calc_dataset(&mut dataset, num, cache);
    dataset
}

#[derive(PartialEq, Debug, Default)]
pub struct Pow {
    pub mix: H256,
    pub value: H256,
}

fn hashimoto<F: Fn(usize) -> H512>(pow_hash: H256, nonce: u64, full_size: usize, lookup: F) -> Pow {
    use std::{mem, ptr};

    let nodes = full_size / HASH_BYTES;
    let words = MIX_BYTES / WORD_BYTES;
    const MIX_HASHES: usize = MIX_BYTES / HASH_BYTES; //2

    let s = unsafe {
        let mut out: [u8; HASH_BYTES] = mem::uninitialized();
        ptr::copy_nonoverlapping(pow_hash.as_ptr(), out.as_mut_ptr(), pow_hash.len());
        ptr::copy_nonoverlapping(
            &nonce as *const u64 as *const u8,
            out[pow_hash.len()..].as_mut_ptr(),
            mem::size_of::<u64>(),
        );
        raw_keccak_512(
            out.as_mut_ptr(),
            HASH_BYTES,
            out.as_ptr(),
            pow_hash.len() + mem::size_of::<u64>(),
        );
        out
    };

    // mix = [s, s];
    let mut mix = [0u8; MIX_BYTES];
    unsafe {
        unroll! {
            for i in 0..2 {
                let ptr: *mut u8 = mix.as_mut_ptr();
                let dst = ptr.offset((i * HASH_BYTES) as isize);
                ptr::copy_nonoverlapping(s.as_ptr(), dst, HASH_BYTES);
            }
        }
    }

    for i in 0..ACCESSES {
        let p = (fnv(
            (i as u32) ^ s.as_ref().read_u32::<LittleEndian>().unwrap(),
            (&mix[(i % words * 4)..])
                .read_u32::<LittleEndian>()
                .unwrap(),
        ) as usize) % (nodes / MIX_HASHES) * MIX_HASHES;

        let mut newdata = [0u8; MIX_BYTES];

        for j in 0..MIX_HASHES {
            let v = lookup(p + j);

            unsafe {
                let ptr: *mut u8 = newdata.as_mut_ptr();
                let dst = ptr.offset((j * HASH_BYTES) as isize);
                ptr::copy_nonoverlapping(v.as_ptr(), dst, HASH_BYTES);
            }
        }
        fnv128(&mut mix, newdata);
    }

    let mut compress_mix = [0u8; MIX_BYTES / 4];
    unroll! {
        for i in 0..8 {
            let j = i * 4;
            let a = fnv(
                (&mix[(j * 4)..]).read_u32::<LittleEndian>().unwrap(),
                (&mix[((j + 1) * 4)..]).read_u32::<LittleEndian>().unwrap(),
            );
            let b = fnv(
                a,
                (&mix[((j + 2) * 4)..]).read_u32::<LittleEndian>().unwrap(),
            );
            let c = fnv(
                b,
                (&mix[((j + 3) * 4)..]).read_u32::<LittleEndian>().unwrap(),
            );

            (&mut compress_mix[j..]).write_u32::<LittleEndian>(c).expect("write_u32");
        }
    }

    let mut result = [0u8; 32];
    unsafe {
        // HASH_BYTES + MIX_BYTES / 4
        let mut buf: [u8; 96] = mem::uninitialized();
        ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr(), s.len());
        ptr::copy_nonoverlapping(
            compress_mix.as_ptr(),
            buf[s.len()..].as_mut_ptr(),
            compress_mix.len(),
        );
        keccak_256(&buf, &mut result);
    }
    Pow {
        mix: H256::from(compress_mix),
        value: H256::from(result),
    }
}

pub fn hashimoto_light(header_hash: H256, nonce: u64, block_height: u64, cache: &[u8]) -> Pow {
    let full_size = get_dataset_size(get_epoch(block_height));
    hashimoto(header_hash, nonce, full_size, |i| {
        calc_dataset_item(cache, i)
    })
}

pub fn hashimoto_full(header_hash: H256, nonce: u64, block_height: u64, dataset: &[u8]) -> Pow {
    let full_size = get_dataset_size(get_epoch(block_height));
    hashimoto(header_hash, nonce, full_size, |i| {
        let mut r = [0u8; 64];
        let index = i * HASH_BYTES;
        r[..].copy_from_slice(&dataset[index..index + HASH_BYTES]);
        H512(r)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use memmap::MmapMut;
    use std::fs;
    use std::path::Path;
    use tempdir::TempDir;

    fn new_memmap<P: AsRef<Path>>(path: P, size: usize) -> MmapMut {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .expect("tests::ethash open file");
        file.set_len(size as u64).expect("tests::ethash set_len");
        unsafe { MmapMut::map_mut(&file).expect("tests::ethash MmapMut map_mut") }
    }

    #[test]
    fn test_recover_boundary() {
        let hash = H256([
            0xf5, 0x7e, 0x6f, 0x3a, 0xcf, 0xc0, 0xdd, 0x4b, 0x5b, 0xf2, 0xbe, 0xe4, 0x0a, 0xb3,
            0x35, 0x8a, 0xa6, 0x87, 0x73, 0xa8, 0xd0, 0x9f, 0x5e, 0x59, 0x5e, 0xab, 0x55, 0x94,
            0x05, 0x52, 0x7d, 0x72,
        ]);
        let mix_hash = H256([
            0x1f, 0xff, 0x04, 0xce, 0xc9, 0x41, 0x73, 0xfd, 0x59, 0x1e, 0x3d, 0x89, 0x60, 0xce,
            0x6b, 0xdf, 0x8b, 0x19, 0x71, 0x04, 0x8c, 0x71, 0xff, 0x93, 0x7b, 0xb2, 0xd3, 0x2a,
            0x64, 0x31, 0xab, 0x6d,
        ]);
        let nonce = 0xd7b3ac70a301a249;
        let boundary_good = H256([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3e, 0x9b, 0x6c, 0x69, 0xbc, 0x2c, 0xe2, 0xa2,
            0x4a, 0x8e, 0x95, 0x69, 0xef, 0xc7, 0xd7, 0x1b, 0x33, 0x35, 0xdf, 0x36, 0x8c, 0x9a,
            0xe9, 0x7e, 0x53, 0x84,
        ]);
        assert_eq!(recover_boundary(&hash, nonce, &mix_hash), boundary_good);
        let boundary_bad = H256([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3a, 0x9b, 0x6c, 0x69, 0xbc, 0x2c, 0xe2, 0xa2,
            0x4a, 0x8e, 0x95, 0x69, 0xef, 0xc7, 0xd7, 0x1b, 0x33, 0x35, 0xdf, 0x36, 0x8c, 0x9a,
            0xe9, 0x7e, 0x53, 0x84,
        ]);
        assert!(recover_boundary(&hash, nonce, &mix_hash) != boundary_bad);
    }

    #[test]
    fn test_get_cache_size() {
        // https://github.com/ethereum/wiki/wiki/Ethash#data-sizes
        assert_eq!(16776896usize, get_cache_size(get_epoch(0)));
        assert_eq!(16776896usize, get_cache_size(get_epoch(1)));
        assert_eq!(16776896usize, get_cache_size(get_epoch(EPOCH_LENGTH - 1)));
        assert_eq!(16907456usize, get_cache_size(get_epoch(EPOCH_LENGTH)));
        assert_eq!(16907456usize, get_cache_size(get_epoch(EPOCH_LENGTH + 1)));
        assert_eq!(
            284950208usize,
            get_cache_size(get_epoch(2046 * EPOCH_LENGTH))
        );
        assert_eq!(
            285081536usize,
            get_cache_size(get_epoch(2047 * EPOCH_LENGTH))
        );
        assert_eq!(
            285081536usize,
            get_cache_size(get_epoch(2048 * EPOCH_LENGTH - 1))
        );
    }

    #[test]
    fn test_get_dataset_size() {
        // https://github.com/ethereum/wiki/wiki/Ethash#data-sizes
        assert_eq!(1073739904usize, get_dataset_size(get_epoch(0)));
        assert_eq!(1073739904usize, get_dataset_size(get_epoch(1)));
        assert_eq!(
            1073739904usize,
            get_dataset_size(get_epoch(EPOCH_LENGTH - 1))
        );
        assert_eq!(1082130304usize, get_dataset_size(get_epoch(EPOCH_LENGTH)));
        assert_eq!(
            1082130304usize,
            get_dataset_size(get_epoch(EPOCH_LENGTH + 1))
        );
        assert_eq!(
            18236833408usize,
            get_dataset_size(get_epoch(2046 * EPOCH_LENGTH))
        );
        assert_eq!(
            18245220736usize,
            get_dataset_size(get_epoch(2047 * EPOCH_LENGTH))
        );
    }

    #[test]
    fn test_seed_hash() {
        let epoch0 = 0 / EPOCH_LENGTH;
        let epoch1 = 486382 / EPOCH_LENGTH;
        let seed0 = seed_hash(epoch0);
        let seed1 = seed_hash(epoch1);
        let hash = [
            241, 175, 44, 134, 39, 121, 245, 239, 228, 236, 43, 160, 195, 152, 46, 7, 199, 5, 253,
            147, 241, 206, 98, 43, 3, 104, 17, 40, 192, 79, 106, 162,
        ];
        assert_eq!(seed0, H256([0u8; 32]));
        assert_eq!(seed1, H256(hash));
    }

    #[test]
    fn test_hashimoto_light() {
        let height = 486382;
        let epoch = get_epoch(height);
        let cache_size = get_cache_size(epoch);
        let seed = seed_hash(epoch);
        let cache = generate_cache(cache_size as usize, &seed);
        let pow_hash = H256([
            0xf5, 0x7e, 0x6f, 0x3a, 0xcf, 0xc0, 0xdd, 0x4b, 0x5b, 0xf2, 0xbe, 0xe4, 0x0a, 0xb3,
            0x35, 0x8a, 0xa6, 0x87, 0x73, 0xa8, 0xd0, 0x9f, 0x5e, 0x59, 0x5e, 0xab, 0x55, 0x94,
            0x05, 0x52, 0x7d, 0x72,
        ]);
        let mix = H256([
            0x1f, 0xff, 0x04, 0xce, 0xc9, 0x41, 0x73, 0xfd, 0x59, 0x1e, 0x3d, 0x89, 0x60, 0xce,
            0x6b, 0xdf, 0x8b, 0x19, 0x71, 0x04, 0x8c, 0x71, 0xff, 0x93, 0x7b, 0xb2, 0xd3, 0x2a,
            0x64, 0x31, 0xab, 0x6d,
        ]);
        let result = H256([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3e, 0x9b, 0x6c, 0x69, 0xbc, 0x2c, 0xe2, 0xa2,
            0x4a, 0x8e, 0x95, 0x69, 0xef, 0xc7, 0xd7, 0x1b, 0x33, 0x35, 0xdf, 0x36, 0x8c, 0x9a,
            0xe9, 0x7e, 0x53, 0x84,
        ]);
        let nonce = 0xd7b3ac70a301a249;

        // difficulty = 0x085657254bd9u64;
        let pow = hashimoto_light(pow_hash, nonce, height, &cache);
        assert_eq!(pow.mix, mix);
        assert_eq!(pow.value, result);
    }

    #[test]
    fn test_hashimoto_full() {
        let height = 486382;
        let epoch = get_epoch(height);
        let cache_size = get_cache_size(epoch);
        let seed = seed_hash(epoch);
        let cache = generate_cache(cache_size as usize, &seed);

        let full_size = get_dataset_size(epoch);
        let dataset = generate_dataset(full_size as usize, &cache);
        let pow_hash = H256([
            0xf5, 0x7e, 0x6f, 0x3a, 0xcf, 0xc0, 0xdd, 0x4b, 0x5b, 0xf2, 0xbe, 0xe4, 0x0a, 0xb3,
            0x35, 0x8a, 0xa6, 0x87, 0x73, 0xa8, 0xd0, 0x9f, 0x5e, 0x59, 0x5e, 0xab, 0x55, 0x94,
            0x05, 0x52, 0x7d, 0x72,
        ]);
        let mix = H256([
            0x1f, 0xff, 0x04, 0xce, 0xc9, 0x41, 0x73, 0xfd, 0x59, 0x1e, 0x3d, 0x89, 0x60, 0xce,
            0x6b, 0xdf, 0x8b, 0x19, 0x71, 0x04, 0x8c, 0x71, 0xff, 0x93, 0x7b, 0xb2, 0xd3, 0x2a,
            0x64, 0x31, 0xab, 0x6d,
        ]);
        let result = H256([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3e, 0x9b, 0x6c, 0x69, 0xbc, 0x2c, 0xe2, 0xa2,
            0x4a, 0x8e, 0x95, 0x69, 0xef, 0xc7, 0xd7, 0x1b, 0x33, 0x35, 0xdf, 0x36, 0x8c, 0x9a,
            0xe9, 0x7e, 0x53, 0x84,
        ]);
        let nonce = 0xd7b3ac70a301a249;

        // difficulty = 0x085657254bd9u64;
        let pow = hashimoto_full(pow_hash, nonce, height, &dataset);
        assert_eq!(pow.mix, mix);
        assert_eq!(pow.value, result);
    }

    #[test]
    fn test_mmap_hashimoto_full() {
        let height = 486382;
        let epoch = get_epoch(height);
        let cache_size = get_cache_size(epoch);
        let seed = seed_hash(epoch);

        let test_path = TempDir::new("test_ethash").unwrap();
        let cache_path = test_path.path().join("cache");
        let dataset_path = test_path.path().join("dataset");

        let mut cache_mmap = new_memmap(cache_path, cache_size);
        let cache_num = cache_size / HASH_BYTES;
        let mut cache = cache_mmap.as_mut();
        calc_cache(&mut cache, cache_num, &seed);

        let full_size = get_dataset_size(epoch);
        let full_num = full_size / HASH_BYTES;
        let mut dataset_mmap = new_memmap(dataset_path, full_size);

        let mut dataset = dataset_mmap.as_mut();
        calc_dataset(&mut dataset, full_num, &cache);
        assert_eq!(dataset.len(), full_size);

        let pow_hash = H256([
            0xf5, 0x7e, 0x6f, 0x3a, 0xcf, 0xc0, 0xdd, 0x4b, 0x5b, 0xf2, 0xbe, 0xe4, 0x0a, 0xb3,
            0x35, 0x8a, 0xa6, 0x87, 0x73, 0xa8, 0xd0, 0x9f, 0x5e, 0x59, 0x5e, 0xab, 0x55, 0x94,
            0x05, 0x52, 0x7d, 0x72,
        ]);
        let mix = H256([
            0x1f, 0xff, 0x04, 0xce, 0xc9, 0x41, 0x73, 0xfd, 0x59, 0x1e, 0x3d, 0x89, 0x60, 0xce,
            0x6b, 0xdf, 0x8b, 0x19, 0x71, 0x04, 0x8c, 0x71, 0xff, 0x93, 0x7b, 0xb2, 0xd3, 0x2a,
            0x64, 0x31, 0xab, 0x6d,
        ]);
        let result = H256([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3e, 0x9b, 0x6c, 0x69, 0xbc, 0x2c, 0xe2, 0xa2,
            0x4a, 0x8e, 0x95, 0x69, 0xef, 0xc7, 0xd7, 0x1b, 0x33, 0x35, 0xdf, 0x36, 0x8c, 0x9a,
            0xe9, 0x7e, 0x53, 0x84,
        ]);
        let nonce = 0xd7b3ac70a301a249;

        // difficulty = 0x085657254bd9u64;
        let pow = hashimoto_full(pow_hash, nonce, height, dataset);
        assert_eq!(pow.mix, mix);
        assert_eq!(pow.value, result);
    }
}
