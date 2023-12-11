mod fvm;
mod sys;

pub use sys::RANDOMX_HASH_SIZE;

pub fn run_randomx(
    k: Vec<u8>,
    h: Vec<u8>,
) -> Result<[u8; RANDOMX_HASH_SIZE], fvm_shared::error::ErrorNumber> {
    unsafe { sys::run_randomx(k.as_ptr(), h.len() as u32, h.as_ptr(), h.len() as u32) }
}
