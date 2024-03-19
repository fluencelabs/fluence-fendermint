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
pub fn run_randomx_batched(
    global_nonce: &Vec<BytesDe>,
    local_nonce: &Vec<BytesDe>,
) -> Result<[u8; BATCHED_HASHES_BYTE_SIZE], fvm_shared::error::ErrorNumber> {
    let global_nonce_raw = to_raw(global_nonce, true);
    // The multiplier 8 here means every element is (u32, u32) pair.
    let global_nonce_raw_byte_len = (global_nonce.len() * 8) as u32;
    let local_nonce_raw = to_raw(local_nonce, false);
    // The multiplier 8 here means every element is (u32, u32) pair.
    let local_nonce_raw_byte_len = (local_nonce.len() * 8) as u32;

    let global_ptr = global_nonce_raw.as_slice().as_ptr();
    let local_ptr = local_nonce_raw.as_slice().as_ptr();
    println!(
        "sdk: glob {:x} g_l {} loc {:x} l_l {}",
        global_ptr as u32, global_nonce_raw_byte_len, local_ptr as u32, local_nonce_raw_byte_len
    );

    unsafe {
        sys::run_randomx_batched(
            global_ptr,
            global_nonce_raw_byte_len,
            local_ptr,
            local_nonce_raw_byte_len,
        )
    }
}

fn to_raw(array: &Vec<BytesDe>, a: bool) -> Vec<u32> {
    array.iter().fold(vec![], |mut acc, v| {
        // This presumes we are in WASM with 32-bit pointers using Little Endian.
        if a {
            println!(
                "sdk to_raw: g ptr {:x} l {}",
                v.0.as_slice().as_ptr() as u32,
                v.0.len() as u32,
            );
        } else {
            println!(
                "sdk to_raw: l ptr {:x} l {}",
                v.0.as_slice().as_ptr() as u32,
                v.0.len() as u32,
            );
        }

        acc.push(v.0.as_slice().as_ptr() as u32);
        acc.push(v.0.len() as u32);
        acc
    })
}
