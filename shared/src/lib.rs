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

/// Size in bytes of a result of RandomX invocation, which is basically a hash.
pub const TARGET_HASH_SIZE: usize = 32;

/// Name of the module where the syscall is supposed to be localed.
pub const SYSCALL_MODULE_NAME: &str = "fluence";

/// Name of the import function (syscall)
/// which will be used to call the actual syscall implementation.
pub const SYSCALL_FUNCTION_NAME: &str = "run_randomx";

/// Size of a batched RandomX invocation result.
pub const MAX_HASHES_BATCH_SIZE: usize = 512;

/// Size in bytes of a batched RandomX invocation result.
pub const BATCHED_HASHES_BYTE_SIZE: usize = MAX_HASHES_BATCH_SIZE * TARGET_HASH_SIZE;

/// Name of a batched version of import function (syscall)
/// which will be used to call the actual syscall implementation.
pub const BATCHED_SYSCALL_FUNCTION_NAME: &str = "run_randomx_batched";
