fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    match try_system_modsecurity() {
        Ok(library) => {
            eprintln!("libmodsecurity found on the system:");
            eprintln!("  Name: {:?}", library.libs);
            eprintln!("  Path: {:?}", library.link_paths);
            eprintln!("  Version: {}", library.version);
        }
        Err(e) => {
            eprintln!("libmodsecurity cannot be found on the system: {e}");
            eprintln!("Vendoring is not supported at this time.");
            std::process::exit(1);
        }
    }
}

/// Tries to use system libmodsecurity. If it is found, it emits the necessary
/// linking directives.
fn try_system_modsecurity() -> Result<pkg_config::Library, pkg_config::Error> {
    let mut cfg = pkg_config::Config::new();
    cfg.range_version("3.0.0"..="3.0.12").probe("modsecurity")
}
