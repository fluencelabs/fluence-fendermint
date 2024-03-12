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

pub use fluence_fendermint_shared::SYSCALL_FUNCTION_NAME;
pub use fluence_fendermint_shared::SYSCALL_MODULE_NAME;
pub use fluence_fendermint_shared::TARGET_HASH_SIZE;

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
    global_nonce_addr: u32,
    global_nonces_len: u32,
    local_nonce_addr: u32,
    local_nonces_len: u32,
) -> Result<Vec<[u8; TARGET_HASH_SIZE]>, ExecutionError> {
    use rayon::prelude::*;

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

    let result = global_nonces
        .par_iter()
        .zip(local_nonces.par_iter())
        .map(|(local_nonce, global_nonce)| {
            compute_randomx_hash(randomx_flags, global_nonce, local_nonce)
        })
        .collect::<Result<Vec<_>, _>>()?;

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

fn from_raw(
    context: &Context<'_, impl Kernel>,
    offset: u32,
    len: u32,
) -> Result<Vec<Vec<u8>>, ExecutionError> {
    use fvm::kernel::ClassifyResult;

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
        let addr = u32::from_le_bytes(raw_result[id..(id + 4)].try_into().unwrap());
        let length = u32::from_le_bytes(raw_result[id + 4..id + 8].try_into().unwrap());

        let result_ = unsafe { Vec::from_raw_parts(addr as _, length as usize, length as usize) };
        result.push(result_)
    }

    Ok(result)
}

fn execution_error(error_code: u32, message: impl Display) -> ExecutionError {
    let error_number = ErrorNumber::from_u32(error_code).unwrap();
    let syscall_error = SyscallError::new(error_number, message);
    ExecutionError::Syscall(syscall_error)
}
