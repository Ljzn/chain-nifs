use std::path::PathBuf;
fn main() {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/liboqs");
    println!("cargo:rerun-if-changed=adapter.c");
    println!("cargo:rerun-if-changed=signing_workspace.c");
    println!("cargo:rerun-if-changed=signing_workspace.h");
    println!("cargo:rerun-if-changed=../../vendor/liboqs");
    let dst = cmake::Config::new(&source)
        .profile("Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("OQS_BUILD_ONLY_LIB", "ON")
        .define("OQS_USE_OPENSSL", "OFF")
        .define("OQS_MINIMAL_BUILD", "SIG_ml_dsa_65")
        .define("OQS_DIST_BUILD", "ON")
        .define("OQS_ENABLE_SIG_ml_dsa_65_avx2", "OFF")
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON")
        .build();
    cc::Build::new()
        .file("adapter.c")
        .file("signing_workspace.c")
        .include(dst.join("include"))
        .include(dst.join("build/include"))
        .include(source.join("src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref"))
        .include(source.join("src/common/pqclean_shims"))
        .define("DILITHIUM_MODE", "3")
        .warnings(true)
        .compile("tensorcash_adapter");
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib64").display()
    );
    println!("cargo:rustc-link-lib=static=oqs");
    if cfg!(target_family = "unix") {
        println!("cargo:rustc-link-lib=pthread");
    }
}
