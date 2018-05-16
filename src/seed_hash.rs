use super::algorithm::{get_epoch, seed_hash};
use super::shared::Epoch;
use bigint::H256;
use keccak::keccak::keccak_256_replace;
use lru_cache::LruCache;
use parking_lot::RwLock;

#[derive(Default)]
pub struct SeedHash {
    inner: RwLock<LruCache<Epoch, H256>>,
}

impl SeedHash {
    pub fn new(cache_size: usize) -> Self {
        SeedHash {
            inner: RwLock::new(LruCache::new(cache_size, false)),
        }
    }

    pub fn get_by_height(&self, block_height: u64) -> H256 {
        let epoch = get_epoch(block_height);
        self.get_by_epoch(epoch)
    }

    pub fn get_by_epoch(&self, epoch: Epoch) -> H256 {
        let cache = self.inner.upgradable_read();
        if let Some(hash) = { cache.get(&epoch).cloned() } {
            return hash;
        } else {
            let mut mut_cache = cache.upgrade();
            let seed =
                if let Some((pre_epoch, pre_hash)) = mut_cache.iter().find(|&(k, _v)| k < &epoch) {
                    Self::compute_seedhash(*pre_hash, *pre_epoch, epoch)
                } else {
                    seed_hash(epoch)
                };
            mut_cache.insert(epoch, seed);
            seed
        }
    }

    #[inline]
    pub fn compute_seedhash(mut hash: H256, start_epoch: u64, end_epoch: u64) -> H256 {
        for _ in start_epoch..end_epoch {
            keccak_256_replace(&mut hash);
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::SeedHash;
    use super::super::algorithm::{seed_hash, EPOCH_LENGTH};

    #[test]
    fn test_seed_hash_cache() {
        let gen = SeedHash::new(3);
        assert_eq!(gen.get_by_height(0), seed_hash(0));
        assert_eq!(gen.get_by_height(EPOCH_LENGTH), seed_hash(1));
        assert_eq!(gen.get_by_height(EPOCH_LENGTH * 2), seed_hash(2));
        assert_eq!(gen.get_by_height(EPOCH_LENGTH * 3), seed_hash(3));
        assert_eq!(gen.get_by_height(EPOCH_LENGTH * 4), seed_hash(4));
        assert_eq!(gen.get_by_height(0), seed_hash(0));
    }
}
