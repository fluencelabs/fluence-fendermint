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

mod sys;

pub use fluence_fendermint_shared::TARGET_HASH_SIZE;

/// Run RandomX in the light mode with the supplied global (K) and local (H) nonce,
/// return its result hash.
pub fn run_randomx(
    global_nonce: &[u8],
    local_nonce: &[u8],
) -> Result<[u8; TARGET_HASH_SIZE], fvm_shared::error::ErrorNumber> {
    unsafe {
        sys::run_randomx(
            global_nonce.as_ptr(),
            global_nonce.len() as u32,
            local_nonce.as_ptr(),
            local_nonce.len() as u32,
        )
    }
}

/// Run RandomX in the light mode with the supplied global (K) and local (H) nonce,
/// return its result hash.
pub fn run_randomx_batched(
    global_nonce: &[Vec<u8>],
    local_nonce: &[Vec<u8>],
) -> Result<[u8; TARGET_HASH_SIZE], fvm_shared::error::ErrorNumber> {
    let global_nonce_raw = to_raw(global_nonce);
    let local_nonce_raw = to_raw(local_nonce);

    unsafe {
        sys::run_randomx_batched(
            global_nonce_raw.as_ptr(),
            global_nonce_raw.len() as u32,
            local_nonce_raw.as_ptr(),
            local_nonce_raw.len() as u32,
        )
    }
}

fn to_raw(array: &[Vec<u8>]) -> Vec<(*const u8, usize)> {
    array.iter().map(|v| (v.as_ptr(), v.len())).collect::<_>()
}
