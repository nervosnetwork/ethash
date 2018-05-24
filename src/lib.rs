#![cfg_attr(feature = "benches", feature(test))]
#![feature(ptr_internals)]

extern crate bigint;
extern crate byteorder;
#[macro_use]
extern crate crunchy;
extern crate keccak;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate memmap;
extern crate parking_lot;
extern crate primal;
extern crate rayon;
#[cfg(test)]
extern crate tempdir;

pub mod algorithm;
mod cache;
mod dataset;
mod ethash;
mod seed_hash;
mod shared;

pub use algorithm::{get_epoch, recover_boundary, Pow};
pub use ethash::Ethash;

#[cfg(feature = "benches")]
mod bench {
    extern crate test;

    use self::test::Bencher;
    use algorithm::{generate_cache, get_cache_size, get_dataset_size, hashimoto_light, seed_hash};
    use bigint::H256;

    const HASH: H256 = H256([
        0xf5, 0x7e, 0x6f, 0x3a, 0xcf, 0xc0, 0xdd, 0x4b, 0x5b, 0xf2, 0xbe, 0xe4, 0x0a, 0xb3, 0x35,
        0x8a, 0xa6, 0x87, 0x73, 0xa8, 0xd0, 0x9f, 0x5e, 0x59, 0x5e, 0xab, 0x55, 0x94, 0x05, 0x52,
        0x7d, 0x72,
    ]);
    const NONCE: u64 = 0xd7b3ac70a301a249;

    #[bench]
    fn bench_light_compute(b: &mut Bencher) {
        let height = 486382;
        let cache_size = get_cache_size(height);
        let full_size = get_dataset_size(height);
        let seed = seed_hash(height);
        let cache = generate_cache(cache_size as usize, &seed);

        b.iter(|| hashimoto_light(HASH, NONCE, full_size as usize, &cache));
    }
}
