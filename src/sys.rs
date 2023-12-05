use crate::fvm::fvm_syscalls;

pub const RANDOMX_HASH_SIZE: usize = 32;

fvm_syscalls! {
    module = "fluence";

    pub fn run_randomx(
        k_addr: *const u8,
        k_len: u32,
        h_addr: *const u8,
        h_len: u32,
    ) -> Result<[u8; RANDOMX_HASH_SIZE]>;
}
