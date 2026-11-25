#[cfg(feature = "native")]
fn main() -> eframe::Result<()> {
    p2p_desktop::run()
}

#[cfg(not(feature = "native"))]
fn main() {
    // diagnostic-guard-allow: static stub guidance, no runtime data or secrets
    eprintln!(
        "This is a stub build. Enable the `native` feature to open the real Rust GUI:\n  \
         cargo run -p p2p-desktop --features native\n\
         `cargo test --workspace` and `--features gui` work without display libraries."
    );
}
