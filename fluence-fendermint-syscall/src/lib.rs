/*
 * Copyright 2024 Fluence Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![warn(rust_2018_idioms)]
#![warn(rust_2021_compatibility)]
#![deny(
    dead_code,
    nonstandard_style,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_unsafe,
    unreachable_patterns
)]

use ccp_randomx::cache::CacheHandle;
use dashmap::DashMap;
use fluence_fendermint_shared::BATCHED_HASHES_BYTE_SIZE;
use lru::LruCache;
use num_traits::cast::FromPrimitive;
use std::collections::HashSet;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

use ccp_randomx::cache::Cache;
use ccp_randomx::flags::RandomXFlags;
use ccp_randomx::vm::RandomXVM;

use fvm::kernel::ExecutionError;
use fvm::kernel::Kernel;
use fvm::kernel::SyscallError;
use fvm::syscalls::Context;
use fvm_shared::error::ErrorNumber;

pub use fluence_fendermint_shared::BATCHED_SYSCALL_FUNCTION_NAME;
pub use fluence_fendermint_shared::SYSCALL_FUNCTION_NAME;
pub use fluence_fendermint_shared::SYSCALL_MODULE_NAME;
pub use fluence_fendermint_shared::TARGET_HASH_SIZE;

const ERRORS_BASE: u32 = 0x10000000;
const RANDOMX_SYSCALL_ERROR_CODE: u32 = 0x10000001;
const INVALID_LENGTH_ERROR_CODE: u32 = 0x10000002;
const ARGUMENTS_HAVE_DIFFERENT_LENGTH_ERROR_CODE: u32 = 0x10000002;
const RANDOMX_HASH_LRU_CACHE_SIZE: usize = 1024;

type RandomXHash = [u8; 32];
type RandomXHashLruMutex = Mutex<LruCache<(Vec<u8>, Vec<u8>), RandomXHash>>;
type RandomXHashLru = OnceLock<RandomXHashLruMutex>;

// (global, local) -> RandomX hash LRU cache.
static mut RANDOMX_HASH_LRU_CACHE: RandomXHashLru = OnceLock::new();

pub fn run_randomx(
    context: Context<'_, impl Kernel>,
    global_nonce_addr: u32,
    global_nonce_len: u32,
    local_nonce_addr: u32,
    local_nonce_len: u32,
) -> Result<[u8; TARGET_HASH_SIZE], ExecutionError> {
    let global_nonce = context
        .memory
        .try_slice(global_nonce_addr, global_nonce_len)?;
    let local_nonce = context
        .memory
        .try_slice(local_nonce_addr, local_nonce_len)?;

    let randomx_flags = RandomXFlags::recommended();
    compute_randomx_hash(randomx_flags, global_nonce, local_nonce)
}

pub fn run_randomx_batched(
    context: Context<'_, impl Kernel>,
    // Pointer to vector of global nonces represented as Vec<Vec<u8>>.
    global_nonce_addr: u32,
    global_nonces_len: u32,
    // Pointer to vector of local nonces represented as Vec<Vec<u8>>.
    local_nonce_addr: u32,
    local_nonces_len: u32,
) -> Result<[u8; BATCHED_HASHES_BYTE_SIZE], ExecutionError> {
    let start = Instant::now();

    // Byte length of arrays must be equal.
    if global_nonces_len != local_nonces_len {
        return Err(execution_error(
            ARGUMENTS_HAVE_DIFFERENT_LENGTH_ERROR_CODE,
            format!(
                "global_nonces length {local_nonces_len}, local_nonces length {global_nonces_len}"
            ),
        ));
    }

    let global_nonces = from_raw(&context, global_nonce_addr, global_nonces_len)?;
    let local_nonces = from_raw(&context, local_nonce_addr, local_nonces_len)?;

    let duration = start.elapsed();
    println!("run_randomx_batched: from_raw took {:?}", duration);

    let hashes = compute_randomx_hashes(global_nonces, local_nonces)?;

    let start = Instant::now();

    // Pack the Vec<RandomXHash> into a single [u8; BATCHED_HASHES_BYTE_SIZE]
    let result = [0u8; BATCHED_HASHES_BYTE_SIZE];

    let result = hashes
        .iter()
        .enumerate()
        .fold(result, |mut acc, (idx, hash)| {
            let array_idx = idx * TARGET_HASH_SIZE;
            acc[array_idx..array_idx + TARGET_HASH_SIZE].copy_from_slice(hash);
            acc
        });

    let duration_pack = start.elapsed();
    println!("run_randomx_batched: pack took {:?}", duration_pack);

    Ok(result)
}

fn compute_randomx_hashes(
    global_nonces: Vec<&[u8]>,
    local_nonces: Vec<&[u8]>,
) -> Result<Vec<RandomXHash>, ExecutionError> {
    let start = Instant::now();
    let randomx_flags = RandomXFlags::recommended();

    let (global_and_local_nonces, cache_results) =
        get_filtered_nonces_and_cached_results(&global_nonces, &local_nonces);

    let unique_global_nonces = get_unique_global_nonces(&global_and_local_nonces);

    let duration_g_nonces = start.elapsed();
    println!(
        "run_randomx_batched: find unique global nonces took {:?}",
        duration_g_nonces
    );

    let unique_caches = get_unique_randomx_caches(&unique_global_nonces, randomx_flags);

    let duration_cr_caches = start.elapsed();
    println!(
        "run_randomx_batched: create unique caches took {:?}",
        duration_cr_caches - duration_g_nonces
    );

    let hashes = compute_or_use_cached_randomx_hashes(
        &global_and_local_nonces,
        &cache_results,
        randomx_flags,
        &unique_caches,
    )?;

    update_randomx_lru_cache(&global_and_local_nonces, &hashes);

    let duration_randomx = start.elapsed();
    println!(
        "run_randomx_batched: randomx took {:?}",
        duration_randomx - duration_cr_caches
    );

    Ok(hashes)
}

fn compute_or_use_cached_randomx_hashes<'nonces>(
    global_and_local_nonces: &Vec<Option<(&'nonces [u8], &'nonces [u8])>>,
    cache_results: &Vec<Option<RandomXHash>>,
    randomx_flags: RandomXFlags,
    unique_caches: &DashMap<&'nonces [u8], Cache>,
) -> Result<Vec<RandomXHash>, ExecutionError> {
    use rayon::prelude::*;

    let hashes = global_and_local_nonces
        .par_iter()
        .zip(cache_results.par_iter())
        .map(|(global_and_local_nonce, cache_result)| {
            match (global_and_local_nonce, cache_result) {
                (Some((global_nonce, local_nonce)), None) => compute_randomx_hash_with_cache(
                    randomx_flags,
                    unique_caches
                        .get(global_nonce)
                        .map(|cache| cache.handle())
                        .unwrap(),
                    local_nonce,
                ),
                (None, Some(cached_hash)) => Ok(*cached_hash), // remove unwrap
                _ => unreachable!("There must be either calculated or cached RandomX hash."),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(hashes)
}

fn get_unique_randomx_caches(
    unique_global_nonces: &HashSet<Vec<u8>>,
    randomx_flags: RandomXFlags,
) -> DashMap<&[u8], Cache> {
    use rayon::prelude::*;

    let unique_caches: DashMap<&[u8], Cache> = DashMap::new();

    unique_global_nonces
        .par_iter()
        .for_each(|unique_global_nonce| {
            let cache = Cache::new(unique_global_nonce, randomx_flags)
                .expect("There must be no error creating RandomX Cache.");
            unique_caches.insert(unique_global_nonce, cache);
        });
    unique_caches
}

fn get_unique_global_nonces(
    global_and_local_nonces: &[Option<(&[u8], &[u8])>],
) -> HashSet<Vec<u8>> {
    let unique_global_nonces: HashSet<Vec<u8>> = global_and_local_nonces
        .iter()
        .filter_map(|el| el.as_ref().map(|(global, _)| (*global).to_owned()))
        .collect();
    unique_global_nonces
}

fn get_filtered_nonces_and_cached_results<'global, 'local>(
    global_nonces: &[&'global [u8]],
    local_nonces: &[&'local [u8]],
) -> (
    Vec<Option<(&'global [u8], &'local [u8])>>,
    Vec<Option<RandomXHash>>,
) {
    let (global_and_local_nonces, cache_results) = unsafe {
        let cache_hash_mutex: &RandomXHashLruMutex = RANDOMX_HASH_LRU_CACHE.get_or_init(|| {
            let lru_max_size = NonZeroUsize::new(RANDOMX_HASH_LRU_CACHE_SIZE)
                .expect("LRU max size must be non-zero");
            Mutex::new(LruCache::new(lru_max_size))
        });

        let mut cache_hash_lru = cache_hash_mutex.lock().unwrap();
        global_nonces.iter().zip(local_nonces.iter()).fold(
            (vec![], vec![]),
            |(mut global_and_local_nonces, mut cache_results), (&global, &local)| {
                // TODO remove explicit types after the measurements are done
                let global_as_vec: Vec<u8> = global.into();
                let local_as_vec: Vec<u8> = local.into();

                // TODO remove after the measurements are done
                let global_as_hex_string = hex::encode(global_as_vec.clone());
                let local_as_hex_string = hex::encode(local_as_vec.clone());

                let cache_result = cache_hash_lru.get(&(global_as_vec, local_as_vec));
                match cache_result {
                    Some(result) => {
                        println!(
                            "Cache hit g: {} l: {}",
                            global_as_hex_string, local_as_hex_string
                        );
                        global_and_local_nonces.push(None);
                        cache_results.push(Some(result.to_owned()));
                    }
                    None => {
                        println!(
                            "Cache miss g: {} l: {}",
                            global_as_hex_string, local_as_hex_string
                        );
                        global_and_local_nonces.push(Some((global, local)));
                        cache_results.push(None);
                    }
                }

                (global_and_local_nonces, cache_results)
            },
        )
    };
    (global_and_local_nonces, cache_results)
}

fn update_randomx_lru_cache(
    global_and_local_nonces: &[Option<(&[u8], &[u8])>],
    hashes: &[RandomXHash],
) {
    for (local_and_global_nonces, hash) in global_and_local_nonces.iter().zip(hashes.iter()) {
        if let Some((global_nonce, local_nonce)) = local_and_global_nonces {
            unsafe {
                let cache_hash_mutex: &RandomXHashLruMutex =
                    RANDOMX_HASH_LRU_CACHE.get_or_init(|| {
                        let lru_max_size = NonZeroUsize::new(RANDOMX_HASH_LRU_CACHE_SIZE)
                            .expect("LRU max size must be non-zero");
                        Mutex::new(LruCache::new(lru_max_size))
                    });
                let mut cache = cache_hash_mutex.lock().unwrap();
                let _ = cache.put(
                    ((*global_nonce).to_owned(), (*local_nonce).to_owned()),
                    *hash,
                );
            }
        }
    }
}

fn compute_randomx_hash(
    randomx_flags: RandomXFlags,
    global_nonce: &[u8],
    local_nonce: &[u8],
) -> Result<[u8; TARGET_HASH_SIZE], ExecutionError> {
    let cache = Cache::new(global_nonce, randomx_flags)
        .map_err(|e| execution_error(RANDOMX_SYSCALL_ERROR_CODE, e))?;
    let vm = RandomXVM::light(cache, randomx_flags)
        .map_err(|e| execution_error(RANDOMX_SYSCALL_ERROR_CODE, e))?;

    Ok(vm.hash(local_nonce).into_slice())
}

fn compute_randomx_hash_with_cache(
    randomx_flags: RandomXFlags,
    cache: CacheHandle,
    local_nonce: &[u8],
) -> Result<[u8; TARGET_HASH_SIZE], ExecutionError> {
    let vm = RandomXVM::light(cache, randomx_flags)
        .map_err(|e| execution_error(RANDOMX_SYSCALL_ERROR_CODE, e))?;

    Ok(vm.hash(local_nonce).into_slice())
}

fn from_raw<'context>(
    context: &'context Context<'_, impl Kernel>,
    offset: u32,
    len: u32,
) -> Result<Vec<&'context [u8]>, ExecutionError> {
    use fvm::kernel::ClassifyResult;

    // Here we process (u32, u32) pairs array created by SDK part in WASM.
    // The first u32 is a pointer to nonce buffer, the second u32 is a length of nonce buffer.
    // This invariant means that every (u32,u32) pair uses 4 + 4 bytes.
    if len % 8 != 0 {
        return Err(execution_error(
            INVALID_LENGTH_ERROR_CODE,
            format!("array length is {}, it's not dividable by 8", len),
        ));
    }

    // Get the outter array data from the memory allocated in wasm runtime.
    let raw_result = context
        .memory
        .get(offset as usize..)
        .and_then(|data| data.get(..len as usize))
        .ok_or_else(|| format!("buffer {} (length {}) out of bounds", offset, len))
        .or_error(ErrorNumber::IllegalArgument)?;

    let mut result = Vec::new();
    // Process the array of (u32, u32) pairs.
    for pair_id in 0..len / 8 {
        let id = (pair_id * 8) as usize;
        // This presumes we are in WASM with 32-bit pointers using Little Endian.
        let addr = u32::from_le_bytes(raw_result[id..(id + 4)].try_into().unwrap());
        let length = u32::from_le_bytes(raw_result[id + 4..id + 8].try_into().unwrap());

        // Get Nonce buffer from the memory allocated in wasm runtime.
        let nonce_buf_from_wasm = context.memory.try_slice(addr, length)?;
        result.push(nonce_buf_from_wasm)
    }

    Ok(result)
}

fn execution_error(error_code: u32, message: impl Display) -> ExecutionError {
    let error_number = ErrorNumber::from_u32(error_code - ERRORS_BASE).unwrap();
    let syscall_error = SyscallError::new(error_number, message);
    ExecutionError::Syscall(syscall_error)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::Mutex;

    use ccp_shared::types::{GlobalNonce, LocalNonce};
    use lru::LruCache;

    use crate::compute_randomx_hashes;
    use crate::get_filtered_nonces_and_cached_results;
    use crate::update_randomx_lru_cache;
    use crate::RandomXHash;
    use crate::RANDOMX_HASH_LRU_CACHE;
    use crate::RANDOMX_HASH_LRU_CACHE_SIZE;

    fn clear_hash_lru_cache() {
        unsafe {
            let cache_hash_mutex: &Mutex<LruCache<(Vec<u8>, Vec<u8>), RandomXHash>> =
                RANDOMX_HASH_LRU_CACHE.get_or_init(|| {
                    let lru_max_size = NonZeroUsize::new(RANDOMX_HASH_LRU_CACHE_SIZE)
                        .expect("LRU max size must be non-zero");
                    Mutex::new(LruCache::new(lru_max_size))
                });
            let mut cache = cache_hash_mutex.lock().unwrap();

            cache.clear();
        }
    }

    #[test]
    fn compute_randomx_hashes_simple() {
        let hex_array: RandomXHash = [
            0x7a, 0x55, 0xef, 0x51, 0x4e, 0x78, 0x14, 0x7c, 0xed, 0x93, 0x28, 0x21, 0x0a, 0x5a,
            0x83, 0x25, 0x2c, 0xaf, 0xa8, 0x96, 0x1e, 0xa1, 0x42, 0x99, 0x4b, 0xe7, 0xbb, 0x85,
            0x18, 0xf6, 0x11, 0x32,
        ];
        let local_nonce = LocalNonce::new(hex_array);

        let global_nonces = (0..4)
            .into_iter()
            .map(|i| {
                let mut hex_array: RandomXHash = [
                    0x06, 0x48, 0xfb, 0x77, 0x5e, 0x2c, 0x0a, 0xcd, 0xe0, 0xa6, 0x67, 0x09, 0x32,
                    0x89, 0x1c, 0xc5, 0x92, 0x3a, 0x86, 0xba, 0x00, 0x66, 0x25, 0x21, 0x0b, 0x1f,
                    0xc7, 0xc9, 0x1a, 0x04, 0x47, 0x4c,
                ];
                hex_array[0] += i;
                GlobalNonce::new(hex_array)
            })
            .collect::<Vec<_>>();

        for _ in 0..5 {
            let global_nonces = global_nonces
                .iter()
                .map(|g_n| g_n.as_ref() as &[u8])
                .collect::<Vec<_>>();
            let _ = compute_randomx_hashes(global_nonces, vec![local_nonce.as_ref()]);
            println!();
        }
    }

    #[test]
    fn get_filtered_nonces_and_cached_results_w_empty_cache() {
        let nonces_num: usize = 5;
        let local_nonces = (0..nonces_num)
            .into_iter()
            .map(|_| LocalNonce::random())
            .collect::<Vec<_>>();

        let local_nonces_bufs = local_nonces
            .iter()
            .map(|l_n| l_n.as_ref() as &[u8])
            .collect::<Vec<_>>();

        let global_nonces = (0..nonces_num)
            .into_iter()
            .map(|i| {
                let mut hex_array: RandomXHash = [
                    0x06, 0x48, 0xfb, 0x77, 0x5e, 0x2c, 0x0a, 0xcd, 0xe0, 0xa6, 0x67, 0x09, 0x32,
                    0x89, 0x1c, 0xc5, 0x92, 0x3a, 0x86, 0xba, 0x00, 0x66, 0x25, 0x21, 0x0b, 0x1f,
                    0xc7, 0xc9, 0x1a, 0x04, 0x47, 0x4c,
                ];
                hex_array[0] += i as u8;
                GlobalNonce::new(hex_array)
            })
            .collect::<Vec<_>>();
        let global_nonces_bufs = global_nonces
            .iter()
            .map(|g_n| g_n.as_ref() as &[u8])
            .collect::<Vec<_>>();

        let (filtered_nonces, cached_hashes) =
            get_filtered_nonces_and_cached_results(&global_nonces_bufs, &local_nonces_bufs);

        assert_eq!(filtered_nonces.len(), nonces_num);
        assert_eq!(cached_hashes.len(), nonces_num);
        cached_hashes
            .iter()
            .for_each(|cached_hash| assert!(cached_hash.is_none()));
        filtered_nonces
            .iter()
            .for_each(|nonces| assert!(nonces.is_some()));
    }

    #[test]
    fn get_filtered_nonces_and_cached_results_non_empty_cache() {
        let nonces_num: usize = 5;
        let local_nonces = (0..nonces_num)
            .into_iter()
            .map(|_| LocalNonce::random())
            .collect::<Vec<_>>();

        let local_nonces_bufs = local_nonces
            .iter()
            .map(|l_n| l_n.as_ref() as &[u8])
            .collect::<Vec<_>>();

        let global_nonces = (0..nonces_num)
            .into_iter()
            .map(|i| {
                let mut hex_array: RandomXHash = [
                    0x06, 0x48, 0xfb, 0x77, 0x5e, 0x2c, 0x0a, 0xcd, 0xe0, 0xa6, 0x67, 0x09, 0x32,
                    0x89, 0x1c, 0xc5, 0x92, 0x3a, 0x86, 0xba, 0x00, 0x66, 0x25, 0x21, 0x0b, 0x1f,
                    0xc7, 0xc9, 0x1a, 0x04, 0x47, 0x4c,
                ];
                hex_array[0] += i as u8;
                GlobalNonce::new(hex_array)
            })
            .collect::<Vec<_>>();
        let global_nonces_bufs = global_nonces
            .iter()
            .map(|g_n| g_n.as_ref() as &[u8])
            .collect::<Vec<_>>();

        let global_nonce = global_nonces[0].as_ref() as &[u8];
        let local_nonce = local_nonces[0].as_ref() as &[u8];
        let nonces = vec![Some((global_nonce, local_nonce))];
        let hashes = vec![[0u8; 32]];
        update_randomx_lru_cache(&nonces, &hashes);

        let (filtered_nonces, cached_hashes) =
            get_filtered_nonces_and_cached_results(&global_nonces_bufs, &local_nonces_bufs);

        assert_eq!(filtered_nonces.len(), nonces_num);
        assert_eq!(cached_hashes.len(), nonces_num);
        assert!(filtered_nonces[0].is_none());
        filtered_nonces
            .iter()
            .skip(1)
            .for_each(|nonces| assert!(nonces.is_some()));
        assert!(cached_hashes[0].is_some());
        cached_hashes
            .iter()
            .skip(1)
            .for_each(|cached| assert!(cached.is_none()));

        clear_hash_lru_cache();
        // }
    }

    #[test]
    fn update_randomx_lru_cache_no_options() {
        let nonce = LocalNonce::random();
        let nonce_buf = nonce.as_ref() as &[u8];
        let nonces = vec![Some((nonce_buf, nonce_buf))];
        let hashes = vec![[0u8; 32]];

        clear_hash_lru_cache();

        update_randomx_lru_cache(&nonces, &hashes);
        unsafe {
            let cache_hash_mutex: &Mutex<LruCache<(Vec<u8>, Vec<u8>), RandomXHash>> =
                RANDOMX_HASH_LRU_CACHE.get_or_init(|| {
                    let lru_max_size = NonZeroUsize::new(RANDOMX_HASH_LRU_CACHE_SIZE)
                        .expect("LRU max size must be non-zero");
                    Mutex::new(LruCache::new(lru_max_size))
                });
            let cache = cache_hash_mutex.lock().unwrap();
            assert_eq!(cache.len(), 1);
        }

        let nonce = LocalNonce::random();
        let nonce_buf = nonce.as_ref() as &[u8];
        let nonces = vec![Some((nonce_buf, nonce_buf))];
        update_randomx_lru_cache(&nonces, &hashes);

        unsafe {
            let cache_hash_mutex: &Mutex<LruCache<(Vec<u8>, Vec<u8>), RandomXHash>> =
                RANDOMX_HASH_LRU_CACHE.get_or_init(|| {
                    let lru_max_size = NonZeroUsize::new(RANDOMX_HASH_LRU_CACHE_SIZE)
                        .expect("LRU max size must be non-zero");
                    Mutex::new(LruCache::new(lru_max_size))
                });
            let cache = cache_hash_mutex.lock().unwrap();
            assert_eq!(cache.len(), 2);
        }

        clear_hash_lru_cache();
    }
}
