use super::algorithm::{get_epoch, hashimoto_full, hashimoto_light, Pow};
use super::cache::{Cache, CacheBuilder};
use super::dataset::{Dataset, DatasetBuilder};
use super::seed_hash::SeedHash;
use super::shared::Epoch;
use bigint::H256;
use lru_cache::LruCache;
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

pub type CacheLru = Arc<RwLock<LruCache<Epoch, Arc<Cache>>>>;
pub type DatasetLru = Arc<RwLock<LruCache<Epoch, Arc<Dataset>>>>;

#[derive(Clone)]
pub struct Ethash {
    pub cache_builder: CacheBuilder,
    pub dataset_builder: DatasetBuilder,
    pub caches: CacheLru,
    pub datasets: DatasetLru,
    pub cache_path: PathBuf,
}

pub const CACHE_SIZE: usize = 4;
pub const DATASET_SIZE: usize = 2;

impl Ethash {
    pub fn new<P: AsRef<Path>>(cache_path: P) -> Ethash {
        Ethash {
            cache_builder: CacheBuilder::new(Arc::new(SeedHash::new(CACHE_SIZE))),
            dataset_builder: DatasetBuilder::new(),
            caches: Arc::new(RwLock::new(LruCache::new(CACHE_SIZE, false))),
            datasets: Arc::new(RwLock::new(LruCache::new(DATASET_SIZE, false))),
            cache_path: cache_path.as_ref().to_path_buf(),
        }
    }

    pub fn get_cache(&self, epoch: Epoch) -> Arc<Cache> {
        let cache = fetch_cache(epoch, &self.caches, &self.cache_builder, &self.cache_path);

        //prepare the next epoch
        let next_epoch = epoch + 1;
        if !self.caches.read().contains_key(&next_epoch) {
            let cache_path = self.cache_path.to_path_buf();
            let cache_builder = self.cache_builder.clone();
            let caches = Arc::clone(&self.caches);
            thread::spawn(move || {
                let cache = cache_builder
                    .build(next_epoch, &cache_path)
                    .expect("generate cache");

                caches.write().insert(next_epoch, Arc::new(cache));
            });
        }
        cache
    }

    pub fn gen_cache(&self, epoch: Epoch) -> Arc<Cache> {
        fetch_cache(epoch, &self.caches, &self.cache_builder, &self.cache_path)
    }

    pub fn gen_dataset(&self, epoch: Epoch) -> Arc<Dataset> {
        let datasets = self.datasets.upgradable_read();
        if !datasets.contains_key(&epoch) {
            info!(target: "ethash", "build dataset epoch {:?} path {:?} start", epoch, &self.cache_path);

            let mut mut_datasets = datasets.upgrade();
            let cache = self.gen_cache(epoch);
            let dataset = self.dataset_builder
                .build(epoch, &self.cache_path, (cache.as_ref()).as_ref())
                .expect("generate dataset");

            let dataset = Arc::new(dataset);
            mut_datasets.insert(epoch, Arc::clone(&dataset));

            info!(target: "ethash", "build dataset epoch {:?} finished !", epoch);
            dataset
        } else {
            Arc::clone(datasets.get(&epoch).expect("key exist checked"))
        }
    }

    pub fn get_dataset(&self, epoch: Epoch) -> Arc<Dataset> {
        let dataset = self.gen_dataset(epoch);
        //prepare the next epoch
        let next_epoch = epoch + 1;
        if !self.datasets.read().contains_key(&next_epoch) {
            let cache_path = self.cache_path.to_path_buf();
            let dataset_builder = self.dataset_builder.clone();
            let datasets = Arc::clone(&self.datasets);

            let caches = Arc::clone(&self.caches);
            let cache_builder = self.cache_builder.clone();
            thread::spawn(move || {
                let cache = fetch_cache(next_epoch, &caches, &cache_builder, &cache_path);
                let dataset = dataset_builder
                    .build(next_epoch, &cache_path, (cache.as_ref()).as_ref())
                    .expect("generate cache");

                datasets.write().insert(next_epoch, Arc::new(dataset));
            });
        }
        dataset
    }

    pub fn compute(&self, block_height: u64, pow_hash: H256, nonce: u64) -> Pow {
        let epoch = get_epoch(block_height);
        let dataset = self.get_dataset(epoch);
        hashimoto_full(pow_hash, nonce, block_height, (dataset.as_ref()).as_ref())
    }

    pub fn light_compute(&self, block_height: u64, pow_hash: H256, nonce: u64) -> Pow {
        let epoch = get_epoch(block_height);
        let cache = self.get_cache(epoch);
        hashimoto_light(pow_hash, nonce, block_height, (cache.as_ref()).as_ref())
    }

    pub fn flush(&self) {
        self.datasets.write().clear();
        self.caches.write().clear();
    }
}

fn fetch_cache(
    epoch: Epoch,
    caches: &CacheLru,
    cache_builder: &CacheBuilder,
    cache_path: &PathBuf,
) -> Arc<Cache> {
    let caches = caches.upgradable_read();
    if !caches.contains_key(&epoch) {
        let mut mut_caches = caches.upgrade();
        let cache = cache_builder
            .build(epoch, cache_path)
            .expect("generate cache");

        let cache = Arc::new(cache);
        mut_caches.insert(epoch, Arc::clone(&cache));
        cache
    } else {
        Arc::clone(caches.get(&epoch).expect("key exist checked"))
    }
}

#[cfg(test)]
mod tests {
    use super::Ethash;
    use bigint::{H256, U256};
    use std::path::PathBuf;
    use tempdir::TempDir;

    struct TestBlock {
        pub height: u64,
        pub pow_hash: H256,
        pub difficulty: U256,
        pub nonce: u64,
        pub mix: H256,
    }

    fn boundary_to_difficulty(boundary: &H256) -> U256 {
        let d = U256::from(*boundary);
        if d <= U256::one() {
            U256::max_value()
        } else {
            ((U256::one() << 255) / d) << 1
        }
    }

    impl TestBlock {
        pub fn verify(&self, ethash: &Ethash) {
            let pow = ethash.compute(self.height, self.pow_hash, self.nonce);
            let difficulty = boundary_to_difficulty(&pow.value);
            assert_eq!(pow.mix, self.mix);
            assert!(difficulty >= self.difficulty);
        }

        pub fn light_verify(&self, ethash: &Ethash) {
            let pow = ethash.light_compute(self.height, self.pow_hash, self.nonce);
            let difficulty = boundary_to_difficulty(&pow.value);
            assert_eq!(pow.mix, self.mix);
            assert!(difficulty >= self.difficulty);
        }
    }

    fn gen_test_block() -> Vec<TestBlock> {
        let block1 = TestBlock {
            height: 22,
            pow_hash: H256::from(
                "372eca2454ead349c3df0ab5d00b0b706b23e49d469387db91811cee0358fc6d",
            ),
            difficulty: U256::from(132416),
            nonce: 0x495732e0ed7a801c,
            mix: H256::from("2f74cdeb198af0b9abe65d22d372e22fb2d474371774a9583c1cc427a07939f5"),
        };

        let block2 = TestBlock {
            height: 30001,
            pow_hash: H256::from(
                "7e44356ee3441623bc72a683fd3708fdf75e971bbe294f33e539eedad4b92b34",
            ),
            difficulty: U256::from(1532671),
            nonce: 0x318df1c8adef7e5e,
            mix: H256::from("144b180aad09ae3c81fb07be92c8e6351b5646dda80e6844ae1b697e55ddde84"),
        };

        let block3 = TestBlock {
            height: 60000,
            pow_hash: H256::from(
                "5fc898f16035bf5ac9c6d9077ae1e3d5fc1ecc3c9fd5bee8bb00e810fdacbaa0",
            ),
            difficulty: U256::from(2467358),
            nonce: 0x50377003e5d830ca,
            mix: H256::from("ab546a5b73c452ae86dadd36f0ed83a6745226717d3798832d1b20b489e82063"),
        };

        vec![block1, block2, block3]
    }

    #[test]
    fn test_verify() {
        let test_path = TempDir::new("test_ethash").unwrap();
        let ethash = Ethash::new(test_path.path().join("ethash_verify"));

        let blocks = gen_test_block();

        for block in blocks {
            block.verify(&ethash);
        }
    }

    #[test]
    fn test_light_verify() {
        let test_path = TempDir::new("test_ethash").unwrap();
        let ethash = Ethash::new(test_path.path().join("ethash_light_verify"));
        let blocks = gen_test_block();

        for block in blocks {
            block.light_verify(&ethash);
        }
    }

    #[test]
    fn test_file_remove() {
        let test_path = TempDir::new("test_ethash").unwrap();
        let files = {
            let ethash = Ethash::new(test_path.path().join("ethash_cache_file"));

            let mut files = Vec::new();

            for ep in 0..6 {
                files.push(ethash.gen_cache(ep).file_path());
            }
            files
        };

        let files = files
            .into_iter()
            .filter(|file| file.exists())
            .collect::<Vec<PathBuf>>();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_compute() {
        let test_path = TempDir::new("test_ethash").unwrap();
        let height = 486382;
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
        let ethash = Ethash::new(test_path.path().join("ethash_compute"));

        let _ = ethash.compute(height, pow_hash, nonce);
        ethash.flush();
        let pow = ethash.compute(height, pow_hash, nonce);

        assert_eq!(pow.mix, mix);
        assert_eq!(pow.value, result);
    }
}
