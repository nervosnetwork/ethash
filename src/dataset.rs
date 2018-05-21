use super::algorithm::{calc_dataset, get_dataset_size, HASH_BYTES, REVISION};
use super::shared::{file_exists, Epoch, NATIVE_ENDIAN};
use memmap::MmapMut;
use parking_lot::Mutex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct DatasetBuilder {
    lock: Arc<Mutex<()>>,
}

impl DatasetBuilder {
    pub fn new() -> Self {
        DatasetBuilder {
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn build(&self, epoch: Epoch, path: &PathBuf, cache: &[u8]) -> io::Result<Dataset> {
        let _guard = self.lock.lock();
        let full_size = get_dataset_size(epoch);
        let file_name = dataset_file_name(epoch);
        let file_path = path.join(file_name);
        let exists = file_exists(&file_path);

        let memmap = if exists {
            load_memmap_dataset(&file_path).or_else(|e| {
                warn!(target: "ethash", "Error load dataset: {:?}", e);
                new_memmap_dataset(&file_path, full_size, cache)
            })
        } else {
            debug!(target: "ethash", "build dataset epoch {:?} path {:?}", epoch, &file_path);
            new_memmap_dataset(&file_path, full_size, cache)
        }?;

        if exists && memmap.as_ref().len() != full_size {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Ethash load dataset size error",
            ))
        } else {
            Ok(Dataset {
                memmap,
                epoch,
                path: path.to_path_buf(),
                lock: Arc::clone(&self.lock),
            })
        }
    }
}

fn load_memmap_dataset<P: AsRef<Path>>(file_path: P) -> io::Result<MmapMut> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)?;
    unsafe { MmapMut::map_mut(&file) }
}

fn new_memmap_dataset<P: AsRef<Path>>(
    file_path: P,
    full_size: usize,
    cache: &[u8],
) -> io::Result<MmapMut> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_path)?;
    file.set_len(full_size as u64)?;
    let mut memmap = unsafe { MmapMut::map_mut(&file)? };

    let hash_num = full_size / HASH_BYTES;
    calc_dataset(memmap.as_mut(), hash_num, cache);
    Ok(memmap)
}

fn dataset_file_name(epoch: Epoch) -> String {
    format!("full-R{:?}-{}{}", REVISION, epoch, NATIVE_ENDIAN)
}

pub struct Dataset {
    pub epoch: Epoch,
    pub memmap: MmapMut,
    pub path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl Drop for Dataset {
    fn drop(&mut self) {
        let _guard = self.lock.lock();
        if let Some(last) = self.epoch
            .checked_sub(2)
            .map(|epoch| self.path.with_file_name(dataset_file_name(epoch)))
        {
            fs::remove_file(last).unwrap_or_else(|error| match error.kind() {
                io::ErrorKind::NotFound => (),
                _ => warn!(target: "ethash", "Error removing stale dataset: {:?}", error),
            });
        }

        let _ = self.memmap.flush();
    }
}

impl Dataset {
    pub fn file_path(&self) -> PathBuf {
        self.path.with_file_name(dataset_file_name(self.epoch))
    }
}

impl AsRef<[u8]> for Dataset {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.memmap.as_ref()
    }
}

impl AsMut<[u8]> for Dataset {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.memmap.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::algorithm::{get_epoch, hashimoto_full};
    use super::super::cache::CacheBuilder;
    use super::super::seed_hash::SeedHash;
    use bigint::H256;
    use std::sync::Arc;
    use tempdir::TempDir;

    #[test]
    fn test_hashimoto_full() {
        let height = 486382;
        let epoch = get_epoch(height);
        let cache_builder = CacheBuilder::new(Arc::new(SeedHash::new(3)));
        let test_path = TempDir::new("test_ethash").unwrap();
        let cache_path = test_path.path().join("dataset_builder");
        let cache = cache_builder.build(epoch, &cache_path).unwrap();

        let dataset_builder = DatasetBuilder::new();
        let dataset = dataset_builder
            .build(epoch, &cache_path, cache.as_ref())
            .unwrap();

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
        let pow = hashimoto_full(pow_hash, nonce, height, dataset.as_ref());
        assert_eq!(pow.mix, mix);
        assert_eq!(pow.value, result);
    }
}
