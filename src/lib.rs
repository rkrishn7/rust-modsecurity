//! A Rust-interface to the [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.
//!
//! If you're looking for low-level FFI bindings to libmodsecurity, check out [modsecurity-sys](./modsecurity-sys/README.md).
//!
//! # Example
//!
//! Block requests with `admin` in the path
//!
//! ```
//! use modsecurity::{ModSecurity, Rules};
//!
//! let ms = ModSecurity::default();
//!
//! let mut rules = Rules::new();
//! rules.add_plain(r#"
//!     SecRuleEngine On
//!
//!     SecRule REQUEST_URI "@rx admin" "id:1,phase:1,deny,status:401"
//! "#).expect("Failed to add rules");
//!
//! let mut transaction = ms
//!     .transaction_builder()
//!     .with_rules(&rules)
//!     .build()
//!     .expect("Error building transaction");
//!
//! transaction.process_uri("http://example.com/admin", "GET", "1.1").expect("Error processing URI");
//! transaction.process_request_headers().expect("Error processing request headers");
//!
//! let intervention = transaction.intervention().expect("Expected intervention");
//!
//! assert_eq!(intervention.status(), 401);
//! ```
//!
//! More examples can be found in the [examples](./examples) directory.
//!
//! # Documentation
//!
//! Information regarding the ModSecurity language can be found in the [ModSecurity Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)).
//!
//! Documentation for this crate can be found on [docs.rs](https://docs.rs/modsecurity).
//!
//! # Requirements
//!
//! This crate requires `libmodsecurity` >= 3.0.9 to be installed on your system.

#![deny(missing_docs)]

#[doc(hidden)]
pub mod bindings;

pub mod error;
pub mod intervention;
pub mod msc;
pub mod rules;
pub mod transaction;

pub use error::ModSecurityError;
pub use intervention::Intervention;

/// Common result for a ModSecurity operation.
pub type ModSecurityResult<T> = Result<T, ModSecurityError>;

// Expose a safe interface to subscribers of the crate that makes use of the
// default generic parameters.

/// See [`transaction::Transaction`].
pub type Transaction<'a> = transaction::Transaction<'a>;

/// See [`msc::ModSecurity`].
pub type ModSecurity = msc::ModSecurity;

/// See [`rules::Rules`].
pub type Rules = rules::Rules;
