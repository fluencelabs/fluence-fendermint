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

use fvm_sdk::sys::fvm_syscalls;

// TODO: use fluence_fendermint_shared::SYSCALL_MODULE_NAME when fvm_syscall allows it.
fvm_syscalls! {
    module = "fluence";

    pub fn run_randomx(
        global_nonce_addr: *const u8,
        global_nonce_len: u32,
        local_nonce_addr: *const u8,
        local_nonce_len: u32,
    ) -> Result<[u8; crate::TARGET_HASH_SIZE]>;
}
