use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    pkg_config::Config::new()
        .atleast_version("3.0.12")
        .probe("modsecurity")
        .unwrap();

    println!("cargo:rustc-link-lib=modsecurity");
    generate_bindings();
}

fn generate_bindings() {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("msc.*")
        .allowlist_type("ModSec.*")
        .allowlist_type("Transaction_t")
        .allowlist_type("Rules_t")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
