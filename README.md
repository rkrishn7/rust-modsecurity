# modsecurity

[![Crates.io](https://img.shields.io/crates/v/modsecurity.svg)](https://crates.io/crates/modsecurity) ![MSRV](https://img.shields.io/badge/msrv-1.58.1-orange) ![Codecov](https://codecov.io/gh/rkrishn7/rust-modsecurity/graph/badge.svg?token=CO5ZQ1UVYJ) ![Check](https://github.com/rkrishn7/rust-modsecurity/actions/workflows/check.yml/badge.svg) ![Safety](https://github.com/rkrishn7/rust-modsecurity/actions/workflows/safety.yml/badge.svg) ![Test](https://github.com/rkrishn7/rust-modsecurity/actions/workflows/test.yml/badge.svg) ![Contributions](https://img.shields.io/badge/contributions-welcome-green)


A Rust-interface to the [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.

If you're looking for low-level FFI bindings to libmodsecurity, check out [modsecurity-sys](./modsecurity-sys/README.md).

## Example

Block requests with `admin` in the path

```rust
use modsecurity::{ModSecurity, Rules};

let ms = ModSecurity::default();

let mut rules = Rules::new();
rules.add_plain(r#"
    SecRuleEngine On

    SecRule REQUEST_URI "@rx admin" "id:1,phase:1,deny,status:401"
"#).expect("Failed to add rules");

let mut transaction = ms
    .transaction_builder()
    .with_rules(&rules)
    .build()
    .expect("Error building transaction");

transaction.process_uri("http://example.com/admin", "GET", "1.1").expect("Error processing URI");
transaction.process_request_headers().expect("Error processing request headers");

let intervention = transaction.intervention().expect("Expected intervention");

assert_eq!(intervention.status(), 401);
```

More examples can be found in the [examples](./examples) directory.

## Documentation

Information regarding the ModSecurity language can be found in the [ModSecurity Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)).

Documentation for this crate can be found on [docs.rs](https://docs.rs/modsecurity).

## Requirements

This crate requires `libmodsecurity` >= 3.0.9 to be installed on your system.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
