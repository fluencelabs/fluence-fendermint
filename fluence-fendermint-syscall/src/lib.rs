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

use randomx_rs::RandomXCache;
use randomx_rs::RandomXFlag;
use randomx_rs::RandomXVM;

use fvm::kernel::ExecutionError;
use fvm::kernel::Kernel;
use fvm::syscalls::Context;

pub use fluence_fendermint_shared::TARGET_HASH_SIZE;

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

    let randomx_flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(randomx_flags, global_nonce).unwrap();
    let vm = RandomXVM::new(randomx_flags, Some(cache), None).unwrap();
    let hash = vm.calculate_hash(local_nonce).unwrap();
    let mut result = [0u8; TARGET_HASH_SIZE];

    // TODO: write RandomX wrapper crate to avoid such copying
    result[..32].copy_from_slice(&hash[..32]);

    Ok(result)
}
