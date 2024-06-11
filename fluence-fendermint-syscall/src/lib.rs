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

use std::collections::HashSet;
use std::fmt::Display;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

use dashmap::DashMap;
use fvm::kernel::ExecutionError;
use fvm::kernel::Kernel;
use fvm::kernel::SyscallError;
use fvm::syscalls::Context;
use fvm_shared::error::ErrorNumber;
use lru::LruCache;
use num_traits::cast::FromPrimitive;
use once_cell::sync::Lazy;

use ccp_randomx::cache::Cache;
use ccp_randomx::cache::CacheHandle;
use ccp_randomx::flags::RandomXFlags;
use ccp_randomx::vm::RandomXVM;
use fluence_fendermint_shared::BATCHED_HASHES_BYTE_SIZE;
pub use fluence_fendermint_shared::BATCHED_SYSCALL_FUNCTION_NAME;
use fluence_fendermint_shared::MAX_HASHES_BATCH_SIZE;
pub use fluence_fendermint_shared::SYSCALL_FUNCTION_NAME;
pub use fluence_fendermint_shared::SYSCALL_MODULE_NAME;
pub use fluence_fendermint_shared::TARGET_HASH_SIZE;

const ERRORS_BASE: u32 = 0x10000000;
const RANDOMX_SYSCALL_ERROR_CODE: u32 = ERRORS_BASE | 1;
const ARGUMENTS_HAVE_DIFFERENT_LENGTH_ERROR_CODE: u32 = ERRORS_BASE | 2;
const TOO_MANY_HASHES_ERROR_CODE: u32 = ERRORS_BASE | 3;
// Cache size can be calculated as
// q99_batch_processing_time * number_of_concurrent_batches floating in the network
// meanwhile LRU size is just big.
const RANDOMX_HASH_LRU_CACHE_SIZE: usize = 1024;

const CACHE_HAS_ELEMENT: &str = "cache has requested element, which is enforced by checks";
const IT_IS_SAFE_TO_LOCK_CACHE: &str = "global cache is safe to lock, it's done in single thread";
const RAW_OFFSET_AND_LEN_ARE_WELL_DEFINED: &str = "offsets and lengths of nonces are well defined";

type RandomXHash = [u8; 32];
type RandomXHashLruMutex = Mutex<LruCache<(Vec<u8>, Vec<u8>), RandomXHash>>;

static RANDOMX_HASH_LRU_CACHE: Lazy<RandomXHashLruMutex> = Lazy::new(|| {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(RANDOMX_HASH_LRU_CACHE_SIZE).expect("LRU max size must be non-zero"),
    ))
});

enum CacheOutcome<'nonce> {
    Hit(Box<RandomXHash>),
    Miss {
        global_nonce: &'nonce [u8],
        local_nonce: &'nonce [u8],
    },
}

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
    global_nonces_count: u32,
    // Pointer to vector of local nonces represented as Vec<Vec<u8>>.
    local_nonce_addr: u32,
    local_nonces_count: u32,
) -> Result<[u8; BATCHED_HASHES_BYTE_SIZE], ExecutionError> {
    let overall_actor_start_time = Instant::now();

    println!("randomx_batched_log: actor was invoked with {global_nonces_len} nonces");

    // Byte length of arrays must be equal.
    if global_nonces_count != local_nonces_count {
        return Err(execution_error(
            ARGUMENTS_HAVE_DIFFERENT_LENGTH_ERROR_CODE,
            format!(
                "global nonces count {global_nonces_count}, local nonces count {local_nonces_count}"
            ),
        ));
    }

    if (global_nonces_count as usize) > MAX_HASHES_BATCH_SIZE {
        return Err(execution_error(
            TOO_MANY_HASHES_ERROR_CODE,
            format!("global_nonces length {global_nonces_count} cannot be larger than {MAX_HASHES_BATCH_SIZE}"),
        ));
    }

    let started = Instant::now();
    let global_nonces = deserialize_nonces(&context, global_nonce_addr, global_nonces_count)?;
    let local_nonces = deserialize_nonces(&context, local_nonce_addr, local_nonces_count)?;
    let deserialization_duration = started.elapsed();
    println!(
        "randomx_batched_duration: arguments_unpacking took {}",
        deserialization_duration.as_nanos() as f64 / 1_000_000f64
    );

    let hashes = compute_randomx_hashes(global_nonces, local_nonces)?;

    // Pack the Vec<RandomXHash> into a single [u8; BATCHED_HASHES_BYTE_SIZE]
    let mut result = [0u8; BATCHED_HASHES_BYTE_SIZE];

    let started = Instant::now();
    for (chunk, hash) in result.chunks_mut(TARGET_HASH_SIZE).zip(&hashes) {
        chunk.copy_from_slice(hash)
    }
    let packing_duration = started.elapsed();
    println!(
        "randomx_batched_duration: result_packing took {}",
        packing_duration.as_nanos() as f64 / 1_000_000f64
    );

    let overall_actor_duration = overall_actor_start_time.elapsed();
    println!(
        "randomx_batched_duration: overall_actor_time {}",
        overall_actor_duration.as_nanos() as f64 / 1_000_000f64
    );

    Ok(result)
}

fn compute_randomx_hashes(
    global_nonces: Vec<&[u8]>,
    local_nonces: Vec<&[u8]>,
) -> Result<Vec<RandomXHash>, ExecutionError> {
    let randomx_flags = RandomXFlags::recommended();

    let started = Instant::now();
    let cache_outcomes = get_filtered_nonces_and_cached_results(&global_nonces, &local_nonces);

    let global_nonce_cache_misses = get_global_nonce_cache_misses(&cache_outcomes);
    let cache_misses = cache_outcomes
        .iter()
        .filter(|outcome| matches!(outcome, CacheOutcome::Miss { .. }))
        .count();
    let cache_hits = cache_outcomes.len() - cache_misses;
    let filter_duration = started.elapsed();
    println!(
        "randomx_batched_duration: filter took {}",
        filter_duration.as_nanos() as f64 / 1_000_000f64
    );

    println!(
        "randomx_batched_log: cache misses {}, cache hits {}",
        cache_misses, cache_hits
    );

    let started = Instant::now();
    let unique_caches = get_unique_randomx_caches(&global_nonce_cache_misses, randomx_flags);
    let cache_init_duration = started.elapsed();
    println!(
        "randomx_batched_duration: cache_init took {}",
        cache_init_duration.as_nanos() as f64 / 1_000_000f64
    );

    let started = Instant::now();
    let hashes =
        compute_or_use_cached_randomx_hashes(&cache_outcomes, randomx_flags, &unique_caches)?;
    let hash_compute_duration = started.elapsed();
    println!(
        "randomx_batched_duration: hash_compute took {}",
        hash_compute_duration.as_nanos() as f64 / 1_000_000f64
    );

    let started = Instant::now();
    update_randomx_lru_cache(&cache_outcomes, &hashes);
    let lru_update_duration = started.elapsed();
    println!(
        "randomx_batched_duration: lru_update took {}",
        lru_update_duration.as_nanos() as f64 / 1_000_000f64
    );

    Ok(hashes)
}

fn compute_or_use_cached_randomx_hashes<'nonces>(
    cache_outcomes: &[CacheOutcome<'nonces>],
    randomx_flags: RandomXFlags,
    unique_caches: &DashMap<&'nonces [u8], Cache>,
) -> Result<Vec<RandomXHash>, ExecutionError> {
    use rayon::prelude::*;

    cache_outcomes
        .par_iter()
        .map(|cache_val| match cache_val {
            CacheOutcome::Hit(result_hash) => Ok(**result_hash),
            CacheOutcome::Miss {
                global_nonce,
                local_nonce,
            } => {
                let randomx_cache = unique_caches.get(global_nonce).expect(CACHE_HAS_ELEMENT);
                compute_randomx_hash_with_cache(randomx_flags, randomx_cache.handle(), local_nonce)
            }
        })
        .collect()
}

fn get_unique_randomx_caches(
    global_nonce_cache_misses: &HashSet<Vec<u8>>,
    randomx_flags: RandomXFlags,
) -> DashMap<&[u8], Cache> {
    use rayon::prelude::*;

    let unique_caches: DashMap<&[u8], Cache> = DashMap::new();

    global_nonce_cache_misses
        .par_iter()
        .for_each(|unique_global_nonce| {
            let cache = Cache::new(unique_global_nonce, randomx_flags)
                .expect("There must be no error creating RandomX Cache.");
            unique_caches.insert(unique_global_nonce, cache);
        });
    unique_caches
}

fn get_global_nonce_cache_misses(cache_outcomes: &[CacheOutcome<'_>]) -> HashSet<Vec<u8>> {
    cache_outcomes
        .iter()
        .filter_map(|el| match el {
            CacheOutcome::Hit(_) => None,
            CacheOutcome::Miss { global_nonce, .. } => Some((*global_nonce).to_owned()),
        })
        .collect()
}

fn get_filtered_nonces_and_cached_results<'nonce>(
    global_nonces: &[&'nonce [u8]],
    local_nonces: &[&'nonce [u8]],
) -> Vec<CacheOutcome<'nonce>> {
    let mut cache_hash_lru = RANDOMX_HASH_LRU_CACHE
        .lock()
        .expect(IT_IS_SAFE_TO_LOCK_CACHE);

    global_nonces
        .iter()
        .zip(local_nonces.iter())
        .map(|(&global_nonce, &local_nonce)| {
            let cache_result = cache_hash_lru.get(&(global_nonce.into(), local_nonce.into()));
            match cache_result {
                Some(result) => CacheOutcome::Hit(Box::new(result.to_owned())),
                None => CacheOutcome::Miss {
                    global_nonce,
                    local_nonce,
                },
            }
        })
        .collect()
}

fn update_randomx_lru_cache(global_and_local_nonces: &[CacheOutcome<'_>], hashes: &[RandomXHash]) {
    let mut cache_hash_lru = RANDOMX_HASH_LRU_CACHE
        .lock()
        .expect(IT_IS_SAFE_TO_LOCK_CACHE);

    for (local_and_global_nonces, hash) in global_and_local_nonces.iter().zip(hashes.iter()) {
        if let CacheOutcome::Miss {
            global_nonce,
            local_nonce,
        } = local_and_global_nonces
        {
            let _ = cache_hash_lru.put(
                ((*global_nonce).to_owned(), (*local_nonce).to_owned()),
                *hash,
            );
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

fn deserialize_nonces<'context>(
    context: &'context Context<'_, impl Kernel>,
    elements_offset: u32,
    elements_count: u32,
) -> Result<Vec<&'context [u8]>, ExecutionError> {
    use fvm::kernel::ClassifyResult;

    // multiply by 8 b/c every element is array and passed as a pair of (offset, len)
    let elements_array_byte_length = 8 * elements_count as usize;

    // Get the outter array data from the memory allocated in wasm runtime.
    let raw_result = context
        .memory
        .get(elements_offset as usize..)
        .and_then(|data| data.get(..elements_array_byte_length))
        .ok_or_else(|| {
            format!(
                "buffer {} (length {}) out of bounds",
                elements_offset, elements_count
            )
        })
        .or_error(ErrorNumber::IllegalArgument)?;

    let mut de_nonces = Vec::with_capacity(elements_count as usize);
    // Process the array of (u32, u32) pairs.
    for element_id in 0..elements_count {
        let element_offset = (element_id * 8) as usize;
        // This presumes we are in WASM with 32-bit pointers using Little Endian.
        let offset = u32::from_le_bytes(
            raw_result[element_offset..(element_offset + 4)]
                .try_into()
                .expect(RAW_OFFSET_AND_LEN_ARE_WELL_DEFINED),
        );
        let length = u32::from_le_bytes(
            raw_result[element_offset + 4..element_offset + 8]
                .try_into()
                .expect(RAW_OFFSET_AND_LEN_ARE_WELL_DEFINED),
        );

        // Get Nonce buffer from the memory allocated in wasm runtime.
        let nonce_buf_from_wasm = context.memory.try_slice(offset, length)?;
        de_nonces.push(nonce_buf_from_wasm)
    }

    Ok(de_nonces)
}

fn execution_error(error_code: u32, message: impl Display) -> ExecutionError {
    let error_number = ErrorNumber::from_u32(error_code - ERRORS_BASE)
        .expect("error codes are guaranteed to be less than maximum number");
    let syscall_error = SyscallError::new(error_number, message);
    ExecutionError::Syscall(syscall_error)
}

#[cfg(test)]
mod tests {

    use ccp_shared::types::{GlobalNonce, LocalNonce};

    use crate::compute_randomx_hashes;
    use crate::get_filtered_nonces_and_cached_results;
    use crate::update_randomx_lru_cache;
    use crate::CacheOutcome;
    use crate::RandomXHash;
    use crate::RANDOMX_HASH_LRU_CACHE;

    fn clear_hash_lru_cache() {
        let mut cache_hash_lru = RANDOMX_HASH_LRU_CACHE.lock().unwrap();
        cache_hash_lru.clear();
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

        let cache_outcomes =
            get_filtered_nonces_and_cached_results(&global_nonces_bufs, &local_nonces_bufs);

        assert_eq!(cache_outcomes.len(), nonces_num);
        for cached_hash in cache_outcomes {
            assert!(matches!(cached_hash, CacheOutcome::Miss { .. }));
        }
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
        let nonces = vec![CacheOutcome::Miss {
            global_nonce,
            local_nonce,
        }];
        let hashes = vec![[0u8; 32]];
        update_randomx_lru_cache(&nonces, &hashes);

        let cache_outcomes =
            get_filtered_nonces_and_cached_results(&global_nonces_bufs, &local_nonces_bufs);

        assert_eq!(cache_outcomes.len(), nonces_num);
        assert!(matches!(cache_outcomes[0], CacheOutcome::Hit(_)));
        for nonces in &cache_outcomes[1..] {
            assert!(matches!(nonces, CacheOutcome::Miss { .. }))
        }

        clear_hash_lru_cache();
    }

    #[test]
    fn update_randomx_lru_cache_no_options() {
        let nonce = LocalNonce::random();
        let nonce_buf = nonce.as_ref() as &[u8];
        let nonces = vec![CacheOutcome::Miss {
            global_nonce: nonce_buf,
            local_nonce: nonce_buf,
        }];
        let hashes = vec![[0u8; 32]];

        clear_hash_lru_cache();

        update_randomx_lru_cache(&nonces, &hashes);
        {
            let cache_hash_lru = RANDOMX_HASH_LRU_CACHE.lock().unwrap();
            assert_eq!(cache_hash_lru.len(), 1);
        }

        let nonce = LocalNonce::random();
        let nonce_buf = nonce.as_ref() as &[u8];
        let nonces = vec![CacheOutcome::Miss {
            global_nonce: nonce_buf,
            local_nonce: nonce_buf,
        }];
        update_randomx_lru_cache(&nonces, &hashes);

        {
            let cache_hash_lru = RANDOMX_HASH_LRU_CACHE.lock().unwrap();
            assert_eq!(cache_hash_lru.len(), 2);
        }

        clear_hash_lru_cache();
    }
}
