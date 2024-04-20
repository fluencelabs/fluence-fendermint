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
use num_traits::cast::FromPrimitive;
use std::fmt::Display;
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

    // Pack the Vec<[u8; 32]> into a single [u8; BATCHED_HASHES_BYTE_SIZE]
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
) -> Result<Vec<[u8; 32]>, ExecutionError> {
    use rayon::prelude::*;
    use rayon::ThreadPoolBuilder;
    use std::collections::HashSet;

    let start = Instant::now();
    let randomx_flags = RandomXFlags::recommended();
    let pool = ThreadPoolBuilder::new().num_threads(8).build().unwrap();
    println!(
        "run_randomx_batched pool threads: {}",
        pool.current_num_threads()
    );

    let mut unique_nonces = HashSet::new();
    for &n in global_nonces.iter() {
        let c = unique_nonces.get(n);
        if c.is_none() {
            unique_nonces.insert(n);
        }
    }
    let duration_g_nonces = start.elapsed();
    println!(
        "run_randomx_batched: find unique global nonces took {:?}",
        duration_g_nonces
    );

    let v = unique_nonces.iter().map(|&c| c).collect::<Vec<_>>();
    let unique_caches = DashMap::new();
    v.par_iter().for_each(|&k| {
        let duration_before_cr = start.elapsed();

        let cache = Cache::new(&k, randomx_flags).unwrap();
        let duration_after_cr = start.elapsed();
        println!(
            "run_randomx_batched: Cache::new() {:?}",
            duration_after_cr - duration_before_cr
        );

        unique_caches.insert(k, cache);
        let duration_after_insert = start.elapsed();
        println!(
            "run_randomx_batched: DashMap::insert {:?}",
            duration_after_insert - duration_after_cr
        );
    });
    let duration_cr_caches = start.elapsed();
    println!(
        "run_randomx_batched: create unique caches took {:?}",
        duration_cr_caches - duration_g_nonces
    );

    let hashes = global_nonces
        .par_iter()
        .zip(local_nonces.par_iter())
        .map(|(global_nonce, local_nonce)| {
            compute_randomx_hash_with_cache(
                randomx_flags,
                unique_caches
                    .get(global_nonce)
                    .map(|cache| cache.handle())
                    .unwrap(),
                local_nonce,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let duration_randomx = start.elapsed();
    println!(
        "run_randomx_batched: randomx took {:?}",
        duration_randomx - duration_cr_caches
    );

    Ok(hashes)
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
    use ccp_shared::types::{GlobalNonce, LocalNonce};

    use crate::compute_randomx_hashes;

    #[test]
    fn compute_randomx_hashes_simple() {
        let hex_array: [u8; 32] = [
            0x7a, 0x55, 0xef, 0x51, 0x4e, 0x78, 0x14, 0x7c, 0xed, 0x93, 0x28, 0x21, 0x0a, 0x5a,
            0x83, 0x25, 0x2c, 0xaf, 0xa8, 0x96, 0x1e, 0xa1, 0x42, 0x99, 0x4b, 0xe7, 0xbb, 0x85,
            0x18, 0xf6, 0x11, 0x32,
        ];
        let local_nonce = LocalNonce::new(hex_array);

        let global_nonces = (0..4)
            .into_iter()
            .map(|i| {
                let mut hex_array: [u8; 32] = [
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
}
