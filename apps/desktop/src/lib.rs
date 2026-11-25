//! Pure Rust desktop shell for the P2P messenger.
//!
//! Layers:
//! - `model`: framework-independent state and pure helpers (always compiled).
//! - `app`: egui widget descriptions (`gui` feature).
//! - `run`: eframe native window (`native` feature).
//!
//! There is no webview, JavaScript runtime, npm, or browser dependency.

#![forbid(unsafe_code)]

pub mod model;

#[cfg(feature = "gui")]
mod app;

#[cfg(feature = "gui")]
pub use app::MessengerApp;

pub use p2p_core::{AppInfo, PROTOCOL_VERSION, app_info};

/// Open the native OS window. Requires the `native` feature and platform
/// windowing/OpenGL development libraries.
#[cfg(feature = "native")]
pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("P2P Messenger")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([920.0, 620.0]),
        ..Default::default()
    };

    eframe::run_native(
        "P2P Messenger",
        options,
        Box::new(|_ctx| Ok(Box::new(MessengerApp::new(app_info())?))),
    )
}
