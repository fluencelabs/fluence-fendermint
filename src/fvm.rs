// Copyright 2021-2023 Protocol Labs
// SPDX-License-Identifier: Apache-2.0, MIT

// copied from https://github.com/filecoin-project/ref-fvm/blob/master/sdk/src/sys/mod.rs#L100
macro_rules! fvm_syscalls {
    // Returns no values.
    (module = $module:literal; $(#[$attrs:meta])* $v:vis fn $name:ident($($args:ident : $args_ty:ty),*$(,)?) -> Result<()>; $($rest:tt)*) => {
        $(#[$attrs])*
        #[allow(clippy::missing_safety_doc)]
        #[allow(clippy::too_many_arguments)]
        $v unsafe fn $name($($args:$args_ty),*) -> Result<(), fvm_shared::error::ErrorNumber> {
            #[link(wasm_import_module = $module)]
            extern "C" {
                #[link_name = stringify!($name)]
                fn syscall($($args:$args_ty),*) -> u32;
            }

            let code = syscall($($args),*);

            if code == 0 {
                Ok(())
            } else {
                Err(num_traits::FromPrimitive::from_u32(code)
                    .expect("syscall returned unrecognized exit code"))
            }
        }
        $crate::fvm::fvm_syscalls! {
            module = $module; $($rest)*
        }
    };
    // Returns a value.
    (module = $module:literal; $(#[$attrs:meta])* $v:vis fn $name:ident($($args:ident : $args_ty:ty),*$(,)?) -> Result<$ret:ty>; $($rest:tt)*) => {
        $(#[$attrs])*
        #[allow(clippy::missing_safety_doc)]
        #[allow(clippy::too_many_arguments)]
        $v unsafe fn $name($($args:$args_ty),*) -> Result<$ret, fvm_shared::error::ErrorNumber> {
            #[link(wasm_import_module = $module)]
            extern "C" {
                #[link_name = stringify!($name)]
                fn syscall(ret: *mut $ret $(, $args : $args_ty)*) -> u32;
            }

            let mut ret = std::mem::MaybeUninit::<$ret>::uninit();
            let code = syscall(ret.as_mut_ptr(), $($args),*);

            if code == 0 {
                Ok(ret.assume_init())
            } else {
                Err(num_traits::FromPrimitive::from_u32(code)
                    .expect("syscall returned unrecognized exit code"))
            }
        }
        $crate::fvm::fvm_syscalls! {
            module = $module;
            $($rest)*
        }
    };
    // Does not return.
    (module = $module:literal; $(#[$attrs:meta])* $v:vis fn $name:ident($($args:ident : $args_ty:ty),*$(,)?) -> !; $($rest:tt)*) => {
        $(#[$attrs])*
        #[allow(clippy::missing_safety_doc)]
        #[allow(clippy::too_many_arguments)]
        $v unsafe fn $name($($args:$args_ty),*) -> ! {
            #[link(wasm_import_module = $module)]
            extern "C" {
                #[link_name = stringify!($name)]
                fn syscall($($args : $args_ty),*) -> u32;
            }

            syscall($($args),*);

            // This should be unreachable unless the syscall has a bug. We abort instead of panicing
            // to help the compiler optimize. It has no way of _proving_ that the syscall doesn't
            // return, so this gives it a way to prove that even if the syscall does return, this
            // function won't.
            std::process::abort()
        }
        $crate::sys::fvm_syscalls! {
            module = $module;
            $($rest)*
        }
    };
    // Base case.
    (module = $module:literal;) => {};
}

pub(crate) use fvm_syscalls;
