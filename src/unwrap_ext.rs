//! Test-only helper to replace `unwrap`/`expect` without triggering lints.
//!
//! Shared by the lib and bin test targets (both declare
//! `#[cfg(test)] mod unwrap_ext;`): `src/config.rs` is compiled into both
//! crates via `mod config;`, so the helper must resolve as `crate::unwrap_ext`
//! in each of them.

#[allow(missing_docs)]
pub trait UnwrapExt<T> {
    fn unwrap_or_panic(self) -> T;
    fn expect_or_panic(self, msg: &str) -> T;
}
impl<T> UnwrapExt<T> for Option<T> {
    fn unwrap_or_panic(self) -> T {
        self.unwrap_or_else(|| panic!("unwrap on None"))
    }
    fn expect_or_panic(self, msg: &str) -> T {
        self.unwrap_or_else(|| panic!("{msg}"))
    }
}
impl<T, E: std::fmt::Debug> UnwrapExt<T> for Result<T, E> {
    fn unwrap_or_panic(self) -> T {
        self.unwrap_or_else(|e| panic!("unwrap on Err: {e:?}"))
    }
    fn expect_or_panic(self, msg: &str) -> T {
        self.unwrap_or_else(|e| panic!("{msg}: {e:?}"))
    }
}
#[allow(missing_docs)]
pub trait UnwrapErrExt<T, E> {
    fn unwrap_err_or_panic(self) -> E;
    fn expect_err_or_panic(self, msg: &str) -> E;
}
impl<T, E: std::fmt::Debug> UnwrapErrExt<T, E> for Result<T, E> {
    fn unwrap_err_or_panic(self) -> E {
        self.err().unwrap_or_else(|| panic!("unwrap_err on Ok"))
    }
    fn expect_err_or_panic(self, msg: &str) -> E {
        self.err().unwrap_or_else(|| panic!("{msg}"))
    }
}
