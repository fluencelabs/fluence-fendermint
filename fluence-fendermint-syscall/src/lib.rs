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

use fluence_fendermint_shared::BATCHED_HASHES_BYTE_SIZE;
use num_traits::cast::FromPrimitive;
use std::fmt::Display;

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
    use rayon::prelude::*;

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

    let randomx_flags = RandomXFlags::recommended();

    let hashes = global_nonces
        .par_iter()
        .zip(local_nonces.par_iter())
        .map(|(local_nonce, global_nonce)| {
            let g: String = global_nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            let l: String = local_nonce
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            println!("sys rx: g 0x{} l 0x{}", g, l);
            compute_randomx_hash(randomx_flags, global_nonce, local_nonce)
        })
        .collect::<Result<Vec<_>, _>>()?;

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

    let r: String = result[0..TARGET_HASH_SIZE]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("sys res: 0x{}", r);

    Ok(result)
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

fn from_raw<'context>(
    context: &'context Context<'_, impl Kernel>,
    offset: u32,
    len: u32,
) -> Result<Vec<&'context [u8]>, ExecutionError> {
    use fvm::kernel::ClassifyResult;

    // This invariant means that every 4 + 4 bytes represent *const u32 + its length.
    if len % 8 != 0 {
        return Err(execution_error(
            INVALID_LENGTH_ERROR_CODE,
            format!("array length is {}, it's not dividable by 8", len),
        ));
    }
    let raw_result = context
        .memory
        .get(offset as usize..)
        .and_then(|data| data.get(..len as usize))
        .ok_or_else(|| format!("buffer {} (length {}) out of bounds", offset, len))
        .or_error(ErrorNumber::IllegalArgument)?;

    let mut result = Vec::new();
    for pair_id in 0..len / 8 {
        let id = (pair_id * 8) as usize;
        // This presumes we are in WASM with 32-bit pointers using Little Endian.
        let addr = u32::from_le_bytes(raw_result[id..(id + 4)].try_into().unwrap());
        let length = u32::from_le_bytes(raw_result[id + 4..id + 8].try_into().unwrap());

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
