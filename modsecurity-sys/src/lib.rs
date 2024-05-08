#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//! Low-level FFI bindings to the C [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.

pub mod bindings;

pub use bindings::*;

// TODO: Write sanity test
