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

mod sys;

pub use sys::RANDOMX_HASH_SIZE;

pub fn run_randomx(
    global_nonce: Vec<u8>,
    local_nonce: Vec<u8>,
) -> Result<[u8; RANDOMX_HASH_SIZE], fvm_shared::error::ErrorNumber> {
    unsafe {
        sys::run_randomx(
            global_nonce.as_ptr(),
            global_nonce.len() as u32,
            local_nonce.as_ptr(),
            local_nonce.len() as u32,
        )
    }
}
