use super::algorithm::{calc_cache, get_cache_size, HASH_BYTES, REVISION};
use super::seed_hash::SeedHash;
use super::shared::{Epoch, NATIVE_ENDIAN};
use bigint::H256;
use memmap::MmapMut;
use parking_lot::Mutex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct CacheBuilder {
    pub seed_hash: Arc<SeedHash>,
    lock: Arc<Mutex<()>>,
}

impl CacheBuilder {
    pub fn new(seed_hash: Arc<SeedHash>) -> Self {
        CacheBuilder {
            seed_hash,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn build(&self, epoch: Epoch, path: &PathBuf) -> io::Result<Cache> {
        let _guard = self.lock.lock();
        let cache_size = get_cache_size(epoch);
        let seed = self.seed_hash.get_by_epoch(epoch);
        let file_name = cache_file_name(epoch);
        let file_path = path.join(file_name);
        let exists = file_path.exists();

        let memmap = if exists {
            load_memmap_cache(&file_path).or_else(|e| {
                warn!(target: "ethash", "Error load cache: {:?}", e);
                new_memmap_cache(&file_path, cache_size, &seed)
            })
        } else {
            debug!(target: "ethash", "build cache epoch {:?} path {:?}", epoch, &file_path);
            fs::create_dir_all(path)?;
            new_memmap_cache(&file_path, cache_size, &seed)
        }?;

        if exists && memmap.as_ref().len() != cache_size {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Ethash load cache size error",
            ))
        } else {
            Ok(Cache {
                memmap,
                epoch,
                path: path.to_path_buf(),
                lock: Arc::clone(&self.lock),
            })
        }
    }
}

fn cache_file_name(epoch: Epoch) -> String {
    format!("cache-R{:?}-{}{}", REVISION, epoch, NATIVE_ENDIAN)
}

fn load_memmap_cache<P: AsRef<Path>>(file_path: P) -> io::Result<MmapMut> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)?;
    unsafe { MmapMut::map_mut(&file) }
}

fn new_memmap_cache<P: AsRef<Path>>(
    file_path: P,
    cache_size: usize,
    seed: &H256,
) -> io::Result<MmapMut> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_path)?;
    file.set_len(cache_size as u64)?;
    let mut memmap = unsafe { MmapMut::map_mut(&file)? };

    let hash_num = cache_size / HASH_BYTES;
    calc_cache(memmap.as_mut(), hash_num, seed);
    Ok(memmap)
}

pub struct Cache {
    pub epoch: Epoch,
    pub memmap: MmapMut,
    pub path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl Drop for Cache {
    fn drop(&mut self) {
        let _guard = self.lock.lock();
        if let Some(last) = self.epoch
            .checked_sub(2)
            .map(|epoch| self.path.join(cache_file_name(epoch)))
        {
            fs::remove_file(last).unwrap_or_else(|error| match error.kind() {
                io::ErrorKind::NotFound => (),
                _ => warn!(target: "ethash", "Error removing stale cache: {:?}", error),
            });
        }

        let _ = self.memmap.flush();
    }
}

impl Cache {
    pub fn file_path(&self) -> PathBuf {
        self.path.join(cache_file_name(self.epoch))
    }
}

impl AsRef<[u8]> for Cache {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.memmap.as_ref()
    }
}

impl AsMut<[u8]> for Cache {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.memmap.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::algorithm::{get_epoch, hashimoto_light};
    use tempdir::TempDir;

    #[test]
    fn test_hashimoto_light() {
        let height = 486382;
        let epoch = get_epoch(height);
        let cache_builder = CacheBuilder::new(Arc::new(SeedHash::new(3)));
        let test_path = TempDir::new("test_ethash").unwrap();
        let cache_path = test_path.path().join("cache_builder");
        let cache = cache_builder.build(epoch, &cache_path).unwrap();

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
        let pow = hashimoto_light(pow_hash, nonce, height, cache.as_ref());
        assert_eq!(pow.mix, mix);
        assert_eq!(pow.value, result);
    }
}
