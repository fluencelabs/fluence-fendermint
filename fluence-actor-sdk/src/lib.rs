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

use fluence_fendermint_shared::BATCHED_HASHES_BYTE_SIZE;
pub use fluence_fendermint_shared::TARGET_HASH_SIZE;
use fvm_ipld_encoding::BytesDe;

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
/// The serialized global and local nonces vectors are passed to syscall as *const u8.
/// Actor will return a error if more than MAX_HASHES_BATCH_SIZE hashes supplied.
pub fn run_randomx_batched(
    global_nonce: &[BytesDe],
    local_nonce: &[BytesDe],
) -> Result<[u8; BATCHED_HASHES_BYTE_SIZE], fvm_shared::error::ErrorNumber> {
    let global_nonce_raw = serialize_nonces(global_nonce);
    let global_nonce_raw_ptr = global_nonce_raw.as_slice().as_ptr();
    let local_nonce_raw = serialize_nonces(local_nonce);
    let local_nonce_raw_ptr = local_nonce_raw.as_slice().as_ptr();

    unsafe {
        sys::run_randomx_batched(
            global_nonce_raw_ptr,
            global_nonce.len() as u32,
            local_nonce_raw_ptr,
            local_nonce.len() as u32,
        )
    }
}

fn serialize_nonces(nonces: &[BytesDe]) -> Vec<u32> {
    let mut se_nonces = Vec::with_capacity(2 * nonces.len());
    for nonce in nonces {
        // This presumes we are in WASM with 32-bit pointers using Little Endian.
        se_nonces.push(nonce.0.as_slice().as_ptr() as u32);
        se_nonces.push(nonce.0.len() as u32);
    }

    se_nonces
}
