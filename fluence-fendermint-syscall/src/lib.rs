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

use num_traits::cast::FromPrimitive;

use randomx_rust_wrapper::cache::Cache;
use randomx_rust_wrapper::flags::RandomXFlags;
use randomx_rust_wrapper::vm::RandomXVM;

use fvm::kernel::ExecutionError;
use fvm::kernel::Kernel;
use fvm::kernel::SyscallError;
use fvm::syscalls::Context;
use fvm_shared::error::ErrorNumber;

pub use fluence_fendermint_shared::SYSCALL_FUNCTION_NAME;
pub use fluence_fendermint_shared::SYSCALL_MODULE_NAME;
pub use fluence_fendermint_shared::TARGET_HASH_SIZE;

const RANDOMX_SYSCALL_ERROR_CODE: u32 = 0x10000001;

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
    let cache = Cache::new(global_nonce, randomx_flags).map_err(|e| {
        let error_number = ErrorNumber::from_u32(RANDOMX_SYSCALL_ERROR_CODE).unwrap();
        let syscall_error = SyscallError::new(error_number, e);
        ExecutionError::Syscall(syscall_error)
    })?;
    let vm = RandomXVM::light(cache, randomx_flags).map_err(|e| {
        let error_number = ErrorNumber::from_u32(RANDOMX_SYSCALL_ERROR_CODE).unwrap();
        let syscall_error = SyscallError::new(error_number, e);
        ExecutionError::Syscall(syscall_error)
    })?;

    let result_hash = vm.hash(local_nonce);
    Ok(result_hash.into_slice())
}
