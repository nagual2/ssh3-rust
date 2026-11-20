//! The build script of the client: on Windows targets the binary carries the
//! resources of the reference client — the icon and the version info (the
//! T7.4 row of the ROADMAP; the live acceptance of the T10.2 found the exe
//! running without an icon while the reference client has one).
//!
//! The resource compilation degrades gracefully: a host without the resource
//! compiler of the target (rc.exe for msvc, windres for gnu) builds a binary
//! without the resources instead of failing the build.

use std::env;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon("./assets/ssh3-icon.ico")
        .set("FileDescription", "SSH3 client")
        .set("ProductName", "SSH3 (ssh3-rust)")
        .set("OriginalFilename", "ssh3.exe");
    if let Ok(version) = env::var("CARGO_PKG_VERSION") {
        resource
            .set("FileVersion", &version)
            .set("ProductVersion", &version);
    }
    if let Err(err) = resource.compile() {
        println!("cargo:warning=the Windows resources of the client were skipped: {err}");
    }
}
