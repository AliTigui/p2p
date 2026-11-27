//! egui description of the native shell. No webview, DOM, Node, or npm.

#[cfg(feature = "native")]
use std::fs::{self, OpenOptions};
#[cfg(feature = "native")]
use std::io::Write;
#[cfg(all(unix, feature = "native"))]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(any(feature = "native", test))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use egui::{
    Button, CentralPanel, Color32, Context, FontFamily, FontId, Frame, Layout, Margin, Panel,
    RichText, Stroke, TextEdit, TextStyle, Ui, Visuals, vec2,
};
use p2p_chat::{
    ChannelGroupStatus, MessengerController, PeerId, QuarantineDeletionPolicy, ReleaseApproval,
    TransferDirection, parse_address, parse_peer_id,
};
use p2p_core::AppInfo;
use p2p_identity::Identity;
use p2p_network::{DialPolicy, RelayMode, TransportPrivacyMode};
use p2p_storage::{Session, StorageError, Vault};
#[cfg(feature = "native")]
use rfd::FileDialog;
use zeroize::Zeroize;

use crate::model::{
    NetworkInfo, NetworkOptions, Theme, UnlockedInfo, VaultOperation, VaultState, file_picker_hint,
    file_send_summary, network_settings_details, next_theme, runtime_banner, security_rows,
};

/// A small Material-inspired token set. These are presentation colors only;
/// runtime state still comes from the vault and network workers.
#[derive(Debug, Clone, Copy)]
struct Palette {
    primary: Color32,
    on_primary: Color32,
    primary_container: Color32,
    on_primary_container: Color32,
    surface: Color32,
    surface_container: Color32,
    outline: Color32,
    text: Color32,
    muted: Color32,
    warning: Color32,
    error: Color32,
    field: Color32,
}

const DARK_PALETTE: Palette = Palette {
    primary: Color32::from_rgb(208, 188, 255),
    on_primary: Color32::from_rgb(56, 30, 114),
    primary_container: Color32::from_rgb(79, 55, 139),
    on_primary_container: Color32::from_rgb(234, 221, 255),
    surface: Color32::from_rgb(20, 19, 24),
    surface_container: Color32::from_rgb(39, 37, 47),
    outline: Color32::from_rgb(105, 99, 118),
    text: Color32::from_rgb(230, 225, 235),
    muted: Color32::from_rgb(174, 168, 185),
    warning: Color32::from_rgb(255, 193, 118),
    error: Color32::from_rgb(242, 184, 181),
    field: Color32::from_rgb(49, 47, 60),
};

const LIGHT_PALETTE: Palette = Palette {
    primary: Color32::from_rgb(103, 80, 164),
    on_primary: Color32::from_rgb(255, 255, 255),
    primary_container: Color32::from_rgb(234, 221, 255),
    on_primary_container: Color32::from_rgb(33, 0, 93),
    surface: Color32::from_rgb(255, 251, 254),
    surface_container: Color32::from_rgb(246, 240, 250),
    outline: Color32::from_rgb(202, 196, 208),
    text: Color32::from_rgb(29, 27, 32),
    muted: Color32::from_rgb(98, 91, 113),
    warning: Color32::from_rgb(129, 76, 0),
    error: Color32::from_rgb(179, 38, 30),
    field: Color32::from_rgb(255, 255, 255),
};

fn palette(theme: Theme) -> Palette {
    match theme {
        Theme::Dark => DARK_PALETTE,
        Theme::Light => LIGHT_PALETTE,
    }
}

fn material_visuals(theme: Theme, p: Palette) -> Visuals {
    let mut visuals = match theme {
        Theme::Dark => Visuals::dark(),
        Theme::Light => Visuals::light(),
    };
    visuals.dark_mode = matches!(theme, Theme::Dark);
    visuals.override_text_color = Some(p.text);
    visuals.weak_text_color = Some(p.muted);
    visuals.hyperlink_color = p.primary;
    visuals.faint_bg_color = p.surface_container;
    visuals.extreme_bg_color = p.field;
    visuals.text_edit_bg_color = Some(p.field);
    visuals.window_fill = p.surface;
    visuals.panel_fill = p.surface;
    visuals.window_stroke = Stroke::NONE;
    visuals.window_corner_radius = 16u8.into();
    visuals.menu_corner_radius = 12u8.into();
    visuals.warn_fg_color = p.warning;
    visuals.error_fg_color = p.error;
    visuals.button_frame = true;
    visuals.collapsing_header_frame = true;
    visuals.selection.bg_fill = p.primary_container;
    visuals.selection.stroke = Stroke::new(1.0, p.primary);

    visuals.widgets.noninteractive.bg_fill = p.surface_container;
    visuals.widgets.noninteractive.weak_bg_fill = p.surface_container;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.outline);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    visuals.widgets.noninteractive.corner_radius = 12u8.into();

    for widget in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.bg_fill = p.surface_container;
        widget.weak_bg_fill = p.surface_container;
        widget.bg_stroke = Stroke::new(1.0, p.outline);
        widget.fg_stroke = Stroke::new(1.0, p.text);
        widget.corner_radius = 20u8.into();
    }
    visuals.widgets.hovered.weak_bg_fill = p.primary_container;
    visuals.widgets.active.weak_bg_fill = p.primary_container;
    visuals.widgets.open.weak_bg_fill = p.primary_container;
    visuals
}

fn apply_material_style(ctx: &Context, theme: Theme, p: Palette) {
    ctx.all_styles_mut(|style| {
        style.text_styles.insert(
            TextStyle::Heading,
            FontId::new(26.0, FontFamily::Proportional),
        );
        style
            .text_styles
            .insert(TextStyle::Body, FontId::new(15.0, FontFamily::Proportional));
        style.text_styles.insert(
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        );
        style.text_styles.insert(
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        );
        style.spacing.item_spacing = vec2(10.0, 8.0);
        style.spacing.button_padding = vec2(14.0, 8.0);
        style.spacing.interact_size = vec2(56.0, 40.0);
        style.spacing.text_edit_width = 320.0;
    });
    ctx.set_visuals(material_visuals(theme, p));
}

fn card<R>(ui: &mut Ui, p: Palette, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .inner_margin(Margin::symmetric(18, 16))
        .fill(p.surface_container)
        .stroke(Stroke::new(1.0, p.outline))
        .corner_radius(16u8)
        .show(ui, add_contents)
        .inner
}

fn card_title(ui: &mut Ui, p: Palette, title: &str) {
    ui.label(
        RichText::new(title.to_uppercase())
            .small()
            .strong()
            .color(p.primary),
    );
    ui.add_space(4.0);
}

fn note(ui: &mut Ui, p: Palette, text: impl Into<RichText>) {
    ui.label(text.into().small().color(p.muted));
}

fn error_label(ui: &mut Ui, p: Palette, text: impl Into<RichText>) {
    ui.colored_label(p.error, text);
}

fn filled_button(ui: &mut Ui, p: Palette, label: impl Into<RichText>) -> bool {
    ui.add(
        Button::new(label.into().color(p.on_primary).strong())
            .fill(p.primary)
            .corner_radius(20u8)
            .min_size(vec2(120.0, 40.0)),
    )
    .clicked()
}

fn tonal_button(ui: &mut Ui, p: Palette, label: impl Into<RichText>) -> bool {
    ui.add(
        Button::new(label.into().color(p.on_primary_container).strong())
            .fill(p.primary_container)
            .corner_radius(20u8)
            .min_size(vec2(88.0, 36.0)),
    )
    .clicked()
}

fn tonal_button_enabled(
    ui: &mut Ui,
    p: Palette,
    label: impl Into<RichText>,
    enabled: bool,
) -> bool {
    let label = label.into();
    if enabled {
        ui.add(
            Button::new(label.color(p.on_primary_container).strong())
                .fill(p.primary_container)
                .corner_radius(20u8)
                .min_size(vec2(88.0, 36.0)),
        )
        .clicked()
    } else {
        ui.add_enabled(
            false,
            Button::new(label)
                .corner_radius(20u8)
                .min_size(vec2(88.0, 36.0)),
        )
        .clicked()
    }
}

/// Write the only plaintext disk output with static errors: no chosen path,
/// file contents, or key material is surfaced in the UI. A pre-existing
/// symlink is refused; newly created files are mode 0600 on Unix.
#[cfg(feature = "native")]
fn write_plain_export(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("Refused to save through a symbolic link".to_owned());
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| "Could not write the selected file".to_owned())?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "Could not restrict the saved file".to_owned())?;
    file.write_all(bytes)
        .map_err(|_| "Could not write the selected file".to_owned())?;
    file.sync_all()
        .map_err(|_| "Could not finish writing the selected file".to_owned())
}

/// A request sent to the blocking worker. The password is moved out of the UI
/// and zeroized by the worker as soon as the vault call finishes.
enum VaultAction {
    Create { username: String, password: String },
    Unlock { password: String },
}

struct VaultOutcome {
    operation: VaultOperation,
    result: Result<Session, StorageError>,
}

pub struct MessengerApp {
    info: AppInfo,
    vault: Vault,
    session: Option<Session>,
    state: VaultState,
    receiver: mpsc::Receiver<VaultOutcome>,
    chat: Option<MessengerController>,
    chat_error: Option<String>,
    peer_address: String,
    contact_peer_id: String,
    member_peer_id: String,
    network_options: NetworkOptions,
    message_text: String,
    channel_name: String,
    username: String,
    password: String,
    confirm_password: String,
    form_error: Option<String>,
    theme: Theme,
}

impl MessengerApp {
    /// Discover the local vault and report its real state. No identity is
    /// generated here: an identity is only created inside a vault.
    pub fn new(info: AppInfo) -> Result<Self, StorageError> {
        let vault = Vault::open(vault_directory())?;
        let state = if vault.exists() {
            VaultState::Locked
        } else {
            VaultState::Missing
        };
        let (_sender, receiver) = mpsc::channel();
        Ok(Self {
            info,
            vault,
            session: None,
            state,
            receiver,
            chat: None,
            chat_error: None,
            peer_address: String::new(),
            contact_peer_id: String::new(),
            member_peer_id: String::new(),
            network_options: NetworkOptions::default(),
            message_text: String::new(),
            channel_name: String::new(),
            username: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            form_error: None,
            theme: Theme::Dark,
        })
    }

    /// The unlocked session, when one actually exists. Private material stays
    /// inside `p2p-storage`; callers receive only public identity data.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    pub fn vault_state(&self) -> &VaultState {
        &self.state
    }

    pub fn network_info(&self) -> Option<NetworkInfo> {
        self.chat.as_ref().map(|chat| NetworkInfo {
            connection: chat.connection_state().description(),
            listen_addresses: chat
                .listen_addresses()
                .iter()
                .map(|address| address.to_string())
                .collect(),
            connected_peers: chat.connection_state().connected_count(),
            privacy: chat.network_privacy_status().clone(),
        })
    }

    fn poll_chat(&mut self) {
        if let Some(chat) = self.chat.as_mut() {
            chat.poll();
            if let Some(error) = chat.last_error() {
                self.chat_error = Some(error.to_owned());
                chat.clear_error();
            }
        }
    }

    /// Start the direct-connect worker and MLS controller with the unlocked
    /// vault identity. No peer is contacted until the user supplies an address.
    /// An encrypted-state restore failure is returned so the caller can keep the
    /// vault in a real failed state instead of showing a fabricated session.
    fn start_chat(&mut self, session: &Session) -> Result<(), String> {
        self.chat = None;
        self.chat_error = None;
        self.peer_address.clear();
        self.contact_peer_id.clear();
        self.member_peer_id.clear();
        self.message_text.clear();
        self.channel_name.clear();
        let config = self.network_options.to_config()?;
        let storage = session.try_clone().map_err(|error| error.to_string())?;
        self.chat = Some(
            MessengerController::start_with_control_log(session.identity(), config, storage)
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    fn connect_peer(&mut self) {
        let relay_only = self.network_options.dial_policy == DialPolicy::RelayOnly;
        let parsed_peer = if relay_only {
            parse_peer_id(&self.peer_address).ok()
        } else {
            None
        };
        let address = if relay_only {
            None
        } else {
            match parse_address(&self.peer_address) {
                Ok(address) => Some(address),
                Err(error) => {
                    self.chat_error = Some(error.to_string());
                    return;
                }
            }
        };
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        self.chat_error = None;
        self.peer_address.clear();
        let result = if relay_only {
            match parsed_peer {
                Some(peer) => chat.connect_relayed(peer),
                None => {
                    self.chat_error = Some("Enter a destination Peer ID".to_owned());
                    return;
                }
            }
        } else if let Some(address) = address {
            chat.connect(address)
        } else {
            return;
        };
        if let Err(error) = result {
            self.chat_error = Some(error.to_string());
        }
    }

    fn start_conversation(&mut self) {
        let peer = match parse_peer_id(&self.contact_peer_id) {
            Ok(peer) => peer,
            Err(error) => {
                self.chat_error = Some(error.to_string());
                return;
            }
        };
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.start_conversation(peer) {
            Ok(_) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn add_member(&mut self) {
        let peer = match parse_peer_id(&self.member_peer_id) {
            Ok(peer) => peer,
            Err(error) => {
                self.chat_error = Some(error.to_string());
                return;
            }
        };
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        let Some(info) = chat.active_info() else {
            self.chat_error = Some("No active MLS group is available.".to_owned());
            return;
        };
        match chat.add_member(info.conversation_id, peer) {
            Ok(()) => {
                self.member_peer_id.clear();
                self.chat_error = None;
            }
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn remove_member(&mut self, peer: PeerId) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        let Some(info) = chat.active_info() else {
            self.chat_error = Some("No active MLS group is available.".to_owned());
            return;
        };
        match chat.remove_member(info.conversation_id, peer) {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn update_member_key(&mut self) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        let Some(info) = chat.active_info() else {
            self.chat_error = Some("No active MLS group is available.".to_owned());
            return;
        };
        match chat.update_member_key(info.conversation_id) {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn select_channel(&mut self, channel_id: [u8; 16]) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        let Some(info) = chat.active_info() else {
            self.chat_error = Some("No active MLS group is available.".to_owned());
            return;
        };
        match chat.select_channel(info.conversation_id, channel_id) {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn create_channel(&mut self) {
        let name = self.channel_name.trim().to_owned();
        if name.is_empty() {
            self.chat_error = Some("Enter a channel name.".to_owned());
            return;
        }
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        let Some(info) = chat.active_info() else {
            self.chat_error = Some("No active MLS group is available.".to_owned());
            return;
        };
        // An empty member list means every current MLS group member. The
        // controller still enforces admin-only policy on the wire path.
        match chat.create_channel(info.conversation_id, &name, Vec::new()) {
            Ok(channel_id) => {
                let _ = chat.select_channel(info.conversation_id, channel_id);
                self.channel_name.clear();
                self.chat_error = None;
            }
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn send_message(&mut self) {
        let text = self.message_text.trim().to_owned();
        if text.is_empty() {
            self.chat_error = Some("Enter a message.".to_owned());
            return;
        }
        let Some(info) = self.chat.as_ref().and_then(|chat| chat.active_info()) else {
            self.chat_error = Some("No joined MLS conversation is active.".to_owned());
            return;
        };
        let Some(channel_id) = info.active_channel else {
            self.chat_error = Some("No channel is selected.".to_owned());
            return;
        };
        let peer = info.peer;
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.send_channel_text(peer, channel_id, &text) {
            Ok(_) => {
                self.message_text.clear();
                self.chat_error = None;
            }
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// Native builds use the OS file picker so sending a file feels like
    /// attaching it to a message instead of copying a path into a form. A
    /// cancellation is silent; only a selected file starts a transfer.
    #[cfg(feature = "native")]
    fn attach_file(&mut self) {
        let Some(path) = FileDialog::new().pick_file() else {
            return;
        };
        self.send_file_path(&path);
    }

    /// Feature-only builds cannot open a native dialog. They report that
    /// honestly rather than exposing a path form in the normal chat flow.
    #[cfg(not(feature = "native"))]
    fn attach_file(&mut self) {
        self.chat_error = Some("File picker requires the native build.".to_owned());
    }

    #[cfg(any(feature = "native", test))]
    fn send_file_path(&mut self, path: &Path) {
        if path.as_os_str().is_empty() || !path.is_file() {
            self.chat_error = Some("Choose an existing file.".to_owned());
            return;
        }
        let Some(peer) = self.chat.as_ref().and_then(|chat| chat.active_peer()) else {
            self.chat_error = Some("No joined MLS conversation is active.".to_owned());
            return;
        };
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.send_file(peer, path) {
            Ok(_) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// Validate the claimed format and invoke the configured scanner, if any.
    /// The default application has no scanner, so this only records structural
    /// validation and an `Unavailable` scan result.
    fn scan_file(&mut self, peer: PeerId) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.scan_file(peer) {
            Ok(_) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// One explicit per-file decision followed by in-memory release. The
    /// plaintext is immediately moved into the encrypted attachment store; it
    /// is never written to disk in the clear here.
    fn approve_and_release_file(&mut self, peer: PeerId) {
        let released = {
            let Some(chat) = self.chat.as_mut() else {
                self.chat_error = Some("Network is not running".to_owned());
                return;
            };
            match chat.approve_and_release_file(peer) {
                Ok(released) => released,
                Err(error) => {
                    self.chat_error = Some(error.to_string());
                    return;
                }
            }
        };
        self.store_released(released);
    }

    fn release_file(&mut self, peer: PeerId) {
        let released = {
            let Some(chat) = self.chat.as_mut() else {
                self.chat_error = Some("Network is not running".to_owned());
                return;
            };
            match chat.release_file(peer) {
                Ok(released) => released,
                Err(error) => {
                    self.chat_error = Some(error.to_string());
                    return;
                }
            }
        };
        self.store_released(released);
    }

    /// Copy the zeroizing release buffer into ciphertext under the vault key.
    /// The buffer is dropped (and zeroized) as soon as this call returns.
    fn store_released(&mut self, released: p2p_chat::ReleasedFile) {
        let result = match self.session.as_ref() {
            Some(session) => session.store_attachment(
                released.name(),
                released.bytes(),
                released.plaintext_hash(),
                released.format_label(),
            ),
            None => Err(StorageError::InvalidProfile("vault is locked".to_owned())),
        };
        match result {
            Ok(_) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// The native OS save dialog is the only path that writes plaintext to
    /// disk. Decryption stays in a zeroizing buffer until that user-chosen
    /// path is written. A cancelled dialog is not an error.
    #[cfg(feature = "native")]
    fn save_attachment(&mut self, id: [u8; 32], suggested_name: &str) {
        let suggested = if p2p_chat::is_safe_file_name(suggested_name) {
            suggested_name
        } else {
            "p2p-messenger-download"
        };
        let Some(path) = FileDialog::new().set_file_name(suggested).save_file() else {
            return;
        };
        let result: Result<(), String> = match self.session.as_ref() {
            Some(session) => session
                .read_attachment(&id)
                .map_err(|error| error.to_string())
                .and_then(|bytes| write_plain_export(&path, bytes.as_slice())),
            None => Err("vault is locked".to_owned()),
        };
        match result {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error),
        }
    }

    /// Explicit deletion of one encrypted attachment. This is never implied
    /// by scanning, approval, release, or quarantine deletion.
    fn delete_attachment(&mut self, id: [u8; 32]) {
        let result = match self.session.as_ref() {
            Some(session) => session.delete_attachment(&id),
            None => Err(StorageError::InvalidProfile("vault is locked".to_owned())),
        };
        match result {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// Cancellation is terminal for an already completed release decision.
    /// Active transfers use abort instead.
    fn cancel_file(&mut self, peer: PeerId) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.cancel_file(peer) {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// Abort an active transfer. This stops local progress and discards
    /// incomplete ciphertext; it does not delete a verified release.
    fn abort_file(&mut self, peer: PeerId) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.abort_file(peer) {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    /// Explicit quarantine deletion. The controller refuses under the default
    /// `Retain` policy and never deletes plaintext or cancels the transfer.
    fn delete_file_quarantine(&mut self, peer: PeerId) {
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        match chat.delete_file_quarantine(peer) {
            Ok(()) => self.chat_error = None,
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    pub fn render(&mut self, ui: &mut Ui) {
        let p = palette(self.theme);
        apply_material_style(ui.ctx(), self.theme, p);

        self.poll_worker();
        self.poll_chat();

        let state = self.state.clone();
        let network_info = self.network_info();
        let unlocked = matches!(&state, VaultState::Unlocked(_));
        let banner = runtime_banner(&self.info, &state, network_info.as_ref());
        let active_conversation = self.chat.as_ref().and_then(|chat| chat.active_info());
        let security = security_rows(&state, network_info.as_ref(), active_conversation.as_ref());

        Panel::top("top_bar")
            .frame(
                Frame::new()
                    .inner_margin(Margin::symmetric(20, 10))
                    .fill(p.surface),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("P2P Messenger").size(20.0).strong());
                    ui.label(RichText::new(banner).small().color(p.warning));
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        if unlocked && tonal_button(ui, p, "Lock") {
                            self.lock();
                        }
                        let label = match self.theme {
                            Theme::Dark => "Light mode",
                            Theme::Light => "Dark mode",
                        };
                        if tonal_button(ui, p, label) {
                            self.theme = next_theme(self.theme);
                        }
                    });
                });
            });

        Panel::right("details")
            .resizable(false)
            .default_size(290.0)
            .frame(
                Frame::new()
                    .inner_margin(Margin::symmetric(12, 12))
                    .fill(p.surface),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| card(ui, p, |ui| {
                    card_title(ui, p, "Observed status");
                    for row in &security {
                        ui.label(RichText::new(row.label).small().color(p.muted));
                        ui.label(RichText::new(&row.value).small());
                        ui.add_space(5.0);
                    }
                    ui.add_space(2.0);
                    note(
                        ui,
                        p,
                        "Statuses reflect observed runtime state. Unimplemented features are shown as such.",
                    );
                }));
            });

        CentralPanel::default()
            .frame(
                Frame::new()
                    .inner_margin(Margin::symmetric(20, 16))
                    .fill(p.surface),
            )
            .show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match &state {
                    VaultState::Missing
                    | VaultState::Failed {
                        operation: VaultOperation::Creating,
                        ..
                    } => self.render_create(ui),
                    VaultState::Busy(VaultOperation::Creating) => {
                        card(ui, p, |ui| {
                            ui.heading("Creating your vault");
                            ui.add_space(8.0);
                            ui.spinner();
                            note(
                                ui,
                                p,
                                "Running Argon2id on a worker thread; the interface stays responsive.",
                            );
                        });
                    }
                    VaultState::Locked
                    | VaultState::Failed {
                        operation: VaultOperation::Unlocking,
                        ..
                    } => self.render_unlock(ui, &state),
                    VaultState::Busy(VaultOperation::Unlocking) => {
                        card(ui, p, |ui| {
                            ui.heading("Unlocking your vault");
                            ui.add_space(8.0);
                            ui.spinner();
                            note(
                                ui,
                                p,
                                "Verifying your password on a worker thread; the interface stays responsive.",
                            );
                        });
                    }
                    VaultState::Unlocked(info) => self.render_unlocked(ui, info),
                }
            });
        });
    }

    fn render_create(&mut self, ui: &mut Ui) {
        let p = palette(self.theme);
        card(ui, p, |ui| {
            ui.heading("Create your local vault");
            ui.add_space(8.0);
            ui.label(
                "A random master key will be generated on this device and wrapped with Argon2id. \
                 Your password is never stored. There is no account, server, or recovery service.",
            );
            ui.add_space(12.0);
            ui.label("Profile name");
            ui.add(TextEdit::singleline(&mut self.username).hint_text("Display name"));
            ui.label("Password");
            ui.add(TextEdit::singleline(&mut self.password).password(true));
            ui.label("Confirm password");
            ui.add(TextEdit::singleline(&mut self.confirm_password).password(true));
            if let VaultState::Failed { message, .. } = &self.state {
                error_label(ui, p, format!("Last attempt failed: {message}"));
            } else {
                self.render_form_error(ui);
            }
            ui.add_space(10.0);
            if filled_button(ui, p, "Create vault") {
                self.submit_create();
            }
            ui.add_space(6.0);
            note(
                ui,
                p,
                "Losing this password means permanent loss of the vault; no recovery is offered.",
            );
        });
    }

    fn render_unlock(&mut self, ui: &mut Ui, state: &VaultState) {
        let p = palette(self.theme);
        card(ui, p, |ui| {
            ui.heading("Unlock your vault");
            ui.add_space(8.0);
            ui.label(format!(
                "Vault location: {}",
                self.vault.directory().display()
            ));
            ui.add_space(12.0);
            ui.label("Password");
            ui.add(TextEdit::singleline(&mut self.password).password(true));
            if let VaultState::Failed { message, .. } = state {
                error_label(ui, p, format!("Last attempt failed: {message}"));
            } else {
                self.render_form_error(ui);
            }
            ui.add_space(10.0);
            if filled_button(ui, p, "Unlock") {
                self.submit_unlock();
            }
        });
    }

    fn render_unlocked(&mut self, ui: &mut Ui, info: &UnlockedInfo) {
        let p = palette(self.theme);
        let conversations = self
            .chat
            .as_ref()
            .map(|chat| chat.conversation_infos())
            .unwrap_or_default();
        let active_conversation = self.chat.as_ref().and_then(|chat| chat.active_info());
        let messages = self
            .chat
            .as_ref()
            .map(|chat| chat.active_messages())
            .unwrap_or_default();
        let transfers = self
            .chat
            .as_ref()
            .map(|chat| chat.file_transfers())
            .unwrap_or_default();
        let deletion_policy = self
            .chat
            .as_ref()
            .map(|chat| chat.quarantine_deletion_policy())
            .unwrap_or_default();
        let local_peer = self
            .session
            .as_ref()
            .map(|session| session.identity().peer_id());
        let attachments_result = self.session.as_ref().map(Session::attachment_infos);
        let attachments = match attachments_result {
            Some(Ok(infos)) => infos,
            Some(Err(error)) => {
                self.chat_error = Some(error.to_string());
                Vec::new()
            }
            None => Vec::new(),
        };

        card(ui, p, |ui| {
            ui.heading("Vault unlocked");
            ui.add_space(8.0);
            ui.label(format!("Profile: {}", info.profile_id));
            ui.label(format!("Peer ID: {}", info.peer_id));
            ui.label(format!("Fingerprint: {}", info.fingerprint));
            note(ui, p, format!("Key protection: {}", info.kdf_summary));
        });

        card(ui, p, |ui| {
            card_title(ui, p, "Direct connection");
            let network = self.network_info();
            match &network {
                Some(net) => {
                    ui.label(format!("Status: {}", net.connection));
                    if net.listen_addresses.is_empty() {
                        ui.label("Listening: waiting for a local address");
                    } else {
                        for address in &net.listen_addresses {
                            ui.label(format!("Listening on: {address}"));
                        }
                    }
                }
                None => {
                    ui.label("Network worker is not running.");
                }
            }
            ui.add_space(8.0);
            if self.network_options.dial_policy == DialPolicy::RelayOnly {
                ui.label("Destination Peer ID (relay-only route)");
                ui.add(TextEdit::singleline(&mut self.peer_address).hint_text("12D3Koo…"));
            } else {
                ui.label("Peer address (must include /p2p/<peer-id>)");
                ui.add(
                    TextEdit::singleline(&mut self.peer_address)
                        .hint_text("/ip4/127.0.0.1/tcp/4001/p2p/12D3…"),
                );
            }
            if self.network_options.transport_mode == TransportPrivacyMode::TorRequired {
                note(
                    ui,
                    p,
                    "All dials use the configured SOCKS5 proxy; there is no direct listener or local DNS lookup.",
                );
            }
            let (connect, disconnect) = ui
                .horizontal(|ui| {
                    (
                        filled_button(ui, p, "Connect"),
                        tonal_button(ui, p, "Disconnect all"),
                    )
                })
                .inner;
            if connect {
                self.connect_peer();
            }
            if disconnect
                && let Some(chat) = self.chat.as_mut()
                && let Err(error) = chat.disconnect_all()
            {
                self.chat_error = Some(error.to_string());
            }
            if let Some(chat) = self.chat.as_ref() {
                let saved = chat.redial_peers();
                if saved.is_empty() {
                    note(ui, p, "Automatic redial: no saved address");
                } else {
                    for peer in saved {
                        let short: String = peer.to_string().chars().take(12).collect();
                        note(
                            ui,
                            p,
                            format!("Redial {short}: {}", chat.redial_state(&peer).description()),
                        );
                    }
                }
            }
            ui.add_space(6.0);
            note(
                ui,
                p,
                "No setup needed: exchange an address with a peer. No relays or discovery by default.",
            );
        });

        card(ui, p, |ui| {
            note(ui, p, "Everything here is optional and off by default.");
            egui::CollapsingHeader::new("Advanced network settings")
                .default_open(false)
                .show(ui, |ui| {
                    note(ui, p, network_settings_details());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Transport route");
                        egui::ComboBox::from_id_salt("p2p_messenger_transport_route")
                            .selected_text(self.network_options.transport_mode.description())
                            .show_ui(ui, |ui| {
                                for (mode, label) in [
                                    (TransportPrivacyMode::Direct, "Direct TCP"),
                                    (TransportPrivacyMode::TorRequired, "SOCKS5/Tor required"),
                                ] {
                                    ui.selectable_value(
                                        &mut self.network_options.transport_mode,
                                        mode,
                                        label,
                                    );
                                }
                            });
                    });
                    ui.label("SOCKS5 proxy address (IP:port, e.g. 127.0.0.1:9050)");
                    ui.add(
                        TextEdit::singleline(&mut self.network_options.socks5_proxy)
                            .hint_text("127.0.0.1:9050"),
                    );
                    ui.checkbox(
                        &mut self.network_options.enable_identify,
                        "Identify (bounded protocol metadata)",
                    );
                    ui.checkbox(
                        &mut self.network_options.enable_ping,
                        "Ping (low frequency)",
                    );
                    ui.add_enabled(
                        self.network_options.transport_mode != TransportPrivacyMode::TorRequired,
                        egui::Checkbox::new(
                            &mut self.network_options.enable_mdns,
                            "mDNS local discovery (advisory only)",
                        ),
                    );
                    ui.checkbox(
                        &mut self.network_options.enable_kad,
                        "Kademlia discovery (user-supplied bootstrap peers only)",
                    );
                    ui.add_enabled(
                        self.network_options.transport_mode != TransportPrivacyMode::TorRequired,
                        egui::Checkbox::new(
                            &mut self.network_options.enable_autonat,
                            "AutoNAT best-effort status probe",
                        ),
                    );
                    ui.add_enabled(
                        self.network_options.dial_policy != DialPolicy::RelayOnly
                            && self.network_options.transport_mode
                                != TransportPrivacyMode::TorRequired,
                        egui::Checkbox::new(
                            &mut self.network_options.enable_dcutr,
                            "DCUtR hole punching when a relayed path exists",
                        ),
                    );
                    ui.horizontal(|ui| {
                        ui.label("Route policy");
                        egui::ComboBox::from_id_salt("p2p_messenger_dial_policy")
                            .selected_text(self.network_options.dial_policy.description())
                            .show_ui(ui, |ui| {
                                for (policy, label) in [
                                    (DialPolicy::DirectAllowed, "Direct allowed"),
                                    (DialPolicy::RelayOnly, "Relay only"),
                                ] {
                                    ui.selectable_value(
                                        &mut self.network_options.dial_policy,
                                        policy,
                                        label,
                                    );
                                }
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Relay mode");
                        egui::ComboBox::from_id_salt("p2p_messenger_relay_mode")
                            .selected_text(self.network_options.relay_mode.description())
                            .show_ui(ui, |ui| {
                                for (mode, label) in [
                                    (RelayMode::Off, "Off"),
                                    (RelayMode::Client, "Client"),
                                    (RelayMode::Server, "Server"),
                                ] {
                                    ui.selectable_value(
                                        &mut self.network_options.relay_mode,
                                        mode,
                                        label,
                                    );
                                }
                            });
                    });
                    ui.label(
                        "Kademlia bootstrap addresses (one per line or comma-separated; /p2p/<peer-id> required)",
                    );
                    ui.add(TextEdit::multiline(
                        &mut self.network_options.kad_bootstrap_peers,
                    ));
                    ui.label(
                        "Relay server addresses (client mode and relay-only routes; direct addresses required)",
                    );
                    ui.add(TextEdit::multiline(&mut self.network_options.relay_servers));
                });
        });

        ui.add_space(8.0);
        card(ui, p, |ui| {
            card_title(ui, p, "MLS groups");

            if conversations.is_empty() {
                ui.label("No MLS conversation has been started in this session.");
            } else {
                for item in &conversations {
                    let pending = item
                        .pending_operation
                        .map(|operation| format!(" · pending {}", operation.description()))
                        .unwrap_or_default();
                    ui.label(format!(
                        "{} · epoch {} · admin {} · {} members · {} channels · {}{}",
                        short(&item.peer.to_string(), 14),
                        item.epoch,
                        short(&item.admin.to_string(), 14),
                        item.members.len(),
                        item.channels.len(),
                        item.status.description(),
                        pending
                    ));
                }
            }

            ui.add_space(8.0);
            ui.label("Connected peer ID for a new 1:1 MLS group");
            ui.add(
                TextEdit::singleline(&mut self.contact_peer_id)
                    .hint_text("12D3Koo… (from the peer's identity panel)"),
            );
            if filled_button(ui, p, "Start encrypted chat") {
                self.start_conversation();
            }

            ui.add_space(8.0);
            match &active_conversation {
                Some(active) => {
                    ui.label(format!(
                        "Active MLS group: {} · epoch {} · {}",
                        short(&active.peer.to_string(), 14),
                        active.epoch,
                        active.status.description()
                    ));
                    ui.label(format!("Admin: {}", short(&active.admin.to_string(), 14)));
                    let pending = match active.pending_operation {
                        Some(operation) => format!(
                            "Pending: {} (waiting for acknowledgements)",
                            operation.description()
                        ),
                        None => "Pending: none".to_owned(),
                    };
                    ui.label(RichText::new(pending).small());
                    ui.label("Members in local view:");
                    for member in &active.members {
                        let role = if Some(*member) == local_peer {
                            " (you)"
                        } else if *member == active.admin {
                            " (admin)"
                        } else {
                            ""
                        };
                        ui.label(format!("  {}{role}", short(&member.to_string(), 14)));
                    }

                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("CHANNELS · PARENT POLICY + DERIVED TEXT GROUPS")
                            .small()
                            .weak(),
                    );
                    for channel in &active.channels {
                        let selected = active.active_channel == Some(channel.channel_id);
                        let marker = if selected { "● " } else { "   " };
                        let policy = if channel.policy_acknowledged {
                            "parent policy acknowledged"
                        } else {
                            "parent policy awaiting receipts"
                        };
                        let group = match channel.group_status {
                            ChannelGroupStatus::DefaultOnParent => {
                                "default text on parent MLS group".to_owned()
                            }
                            ChannelGroupStatus::DerivedReady => {
                                "derived text group ready".to_owned()
                            }
                            ChannelGroupStatus::DerivedSettingUp { awaited } => format!(
                                "derived setup pending ({awaited} acknowledgement(s) outstanding)"
                            ),
                            ChannelGroupStatus::Missing => {
                                "derived text group not started".to_owned()
                            }
                        };
                        let label = format!(
                            "{marker}{} · rev {} · {} allowed · {policy} · {group}",
                            short(&channel.name, 20),
                            channel.revision,
                            channel.members.len()
                        );
                        if tonal_button(ui, p, label) {
                            self.select_channel(channel.channel_id);
                        }
                    }
                    ui.add(
                        TextEdit::singleline(&mut self.channel_name)
                            .hint_text("New channel name (admin only)"),
                    );
                    let idle = active.pending_operation.is_none();
                    let can_create = idle && local_peer == Some(active.admin);
                    if tonal_button_enabled(ui, p, "Create channel", can_create) {
                        self.create_channel();
                    }
                    ui.label(
                        RichText::new("Default chat is private to the parent group; restricted channels get a separate group after setup.")
                            .small()
                            .weak(),
                    );
                    egui::CollapsingHeader::new("Channel security details")
                        .default_open(false)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(
                                    "Channel names, membership, and policy frames stay in signed CHN1 frames on the parent MLS group, readable by every parent member. Default-channel text also uses the parent group. Non-default text and receipts use an independent bound MLS group after setup converges; sending is blocked until then. This is not a complete cryptographic channel ACL.",
                                )
                                .small()
                                .weak(),
                            );
                        });

                    if tonal_button_enabled(ui, p, "Refresh my MLS key", idle) {
                        self.update_member_key();
                    }
                    ui.label("Connected peer ID to add to this group");
                    ui.add(
                        TextEdit::singleline(&mut self.member_peer_id)
                            .hint_text("12D3Koo… (must already be directly connected)"),
                    );
                    if tonal_button_enabled(ui, p, "Add member", idle) {
                        self.add_member();
                    }
                    if let Some(local) = local_peer {
                        for member in &active.members {
                            if *member != local && *member != active.admin {
                                let label = format!("Remove {}", short(&member.to_string(), 14));
                                if tonal_button_enabled(ui, p, label, idle) {
                                    self.remove_member(*member);
                                }
                            }
                        }
                    }
                    ui.label(
                        RichText::new("Only the admin changes membership. Changes wait for everyone to acknowledge.")
                            .small()
                            .weak(),
                    );

                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .show(ui, |ui| {
                            if messages.is_empty() {
                                ui.label("No decrypted messages in this session.");
                            }
                            for message in &messages {
                                let sender = if message.origin == p2p_chat::MessageOrigin::Local {
                                    "You".to_owned()
                                } else {
                                    short(&message.peer.to_string(), 14)
                                };
                                let delivery = match message.delivery {
                                    Some(state) => state.description(),
                                    None => "Received",
                                };
                                ui.label(format!("{sender}: {} [{delivery}]", message.text));
                            }
                        });
                    ui.add(TextEdit::singleline(&mut self.message_text).hint_text("Message"));
                    let (send, attach) = ui
                        .horizontal(|ui| {
                            (
                                filled_button(ui, p, "Send"),
                                tonal_button(ui, p, "Attach file"),
                            )
                        })
                        .inner;
                    if send {
                        self.send_message();
                    }
                    if attach {
                        self.attach_file();
                    }
                    note(ui, p, file_picker_hint());
                }
                None => {
                    ui.label("Start or join an MLS conversation before sending messages.");
                }
            }
        });

        ui.add_space(8.0);
        card(ui, p, |ui| {
            card_title(ui, p, "Files");
            if transfers.is_empty() {
                ui.label("No file transfers in this session.");
            } else {
                egui::ScrollArea::vertical()
                .max_height(140.0)
                .show(ui, |ui| {
                    for transfer in &transfers {
                        let direction = match transfer.direction {
                            TransferDirection::Outgoing => "Out",
                            TransferDirection::Incoming => "In",
                        };
                        ui.label(format!(
                            "{direction} {} · {} bytes · {}/{} chunks · {}",
                            transfer.name,
                            transfer.size,
                            transfer.chunks_done,
                            transfer.chunks_total,
                            transfer.status.description()
                        ));
                        let release = if transfer.released {
                            "released and stored encrypted"
                        } else {
                            "not released"
                        };
                        let quarantine = if transfer.quarantine_deleted {
                            "deleted by explicit request"
                        } else {
                            "retained (ciphertext)"
                        };
                        let format = transfer
                            .format
                            .map(|value| value.description())
                            .unwrap_or("not validated");
                        ui.label(
                            RichText::new(format!(
                                "Scan: {} · Format: {format} · Approval: {} · Release: {release} · Quarantine: {quarantine}",
                                transfer.scan.description(),
                                transfer.approval.description()
                            ))
                            .small()
                            .weak(),
                        );
                        if transfer.status.active() && tonal_button(ui, p, "Abort transfer") {
                            self.abort_file(transfer.peer);
                        }
                        if transfer.direction == TransferDirection::Incoming && !transfer.released {
                            if transfer.status.completed()
                                && matches!(
                                    transfer.approval,
                                    ReleaseApproval::NotReady
                                        | ReleaseApproval::Pending
                                        | ReleaseApproval::Approved
                                )
                                && tonal_button(ui, p, "Validate format / scan if configured")
                            {
                                self.scan_file(transfer.peer);
                            }
                            match transfer.approval {
                                ReleaseApproval::Pending => {
                                    if filled_button(ui, p, "Approve and store encrypted") {
                                        self.approve_and_release_file(transfer.peer);
                                    }
                                    if tonal_button(ui, p, "Cancel release") {
                                        self.cancel_file(transfer.peer);
                                    }
                                }
                                ReleaseApproval::Approved => {
                                    if filled_button(ui, p, "Store encrypted in vault") {
                                        self.release_file(transfer.peer);
                                    }
                                    if tonal_button(ui, p, "Cancel release") {
                                        self.cancel_file(transfer.peer);
                                    }
                                }
                                _ => {}
                            }
                        }
                        if transfer.direction == TransferDirection::Incoming
                            && !transfer.quarantine_deleted
                            && transfer.status.completed()
                            && deletion_policy == QuarantineDeletionPolicy::Explicit
                            && (transfer.released || transfer.approval == ReleaseApproval::Cancelled)
                            && tonal_button(ui, p, "Delete quarantine ciphertext")
                        {
                            self.delete_file_quarantine(transfer.peer);
                        }
                    }
                });
            }
            ui.add_space(8.0);
            note(ui, p, file_send_summary());
            egui::CollapsingHeader::new("File safety details")
                .default_open(false)
                .show(ui, |ui| {
                    note(
                        ui,
                        p,
                        "Incoming ciphertext is quarantined. Structural validation supports TXT, PNG, and GIF only; it is not malware detection. Integrity verification is not a scan, and scanning is unavailable without an independent scanner. Release requires a clean scanner result, a validated format, an allowed extension, and explicit per-file approval; released bytes are copied into the encrypted vault, never written as plaintext here. Quarantine ciphertext for a verified transfer is retained by default and is deleted only by an explicit request where policy permits; aborting an incomplete transfer removes its partial ciphertext. Active transfers have an inactivity timeout and can be aborted; release cancellation applies only after verification. Filesystem deletion is not secure erasure. This app configures no scanner or allowed extensions, so no release action appears by default.",
                    );
                });
        });

        ui.add_space(8.0);
        card(ui, p, |ui| {
            card_title(ui, p, "Encrypted attachments");
            if attachments.is_empty() {
                ui.label("No attachments are stored in the encrypted vault.");
            } else {
                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .show(ui, |ui| {
                        for item in &attachments {
                            ui.label(format!(
                                "{} · {} bytes · {}",
                                item.name,
                                item.size,
                                item.format.as_deref().unwrap_or("not validated")
                            ));
                            ui.horizontal(|ui| {
                                #[cfg(feature = "native")]
                                if tonal_button(ui, p, "Save via OS dialog") {
                                    self.save_attachment(item.id, &item.name);
                                }
                                if tonal_button(ui, p, "Delete stored attachment") {
                                    self.delete_attachment(item.id);
                                }
                            });
                        }
                    });
            }
            note(
                ui,
                p,
                "Attachments are ciphertext at rest in the vault. The native OS save dialog is the only plaintext disk write and requires a path you choose; a cancelled dialog writes nothing.",
            );
            #[cfg(not(feature = "native"))]
            note(
                ui,
                p,
                "OS save dialog is available only in the native build.",
            );
        });

        ui.add_space(8.0);
        card(ui, p, |ui| {
            if let Some(error) = &self.chat_error {
                error_label(ui, p, error);
            }
            note(
                ui,
                p,
                "Restored groups keep their encrypted state. Messages and setup secrets do not survive restart; no malware scanner is configured.",
            );
            ui.add_space(10.0);
            if tonal_button(ui, p, "Lock vault") {
                self.lock();
            }
        });
    }

    fn render_form_error(&self, ui: &mut Ui) {
        if let Some(error) = &self.form_error {
            error_label(ui, palette(self.theme), error);
        }
    }

    fn submit_create(&mut self) {
        if !matches!(
            self.state,
            VaultState::Missing
                | VaultState::Failed {
                    operation: VaultOperation::Creating,
                    ..
                }
        ) {
            return;
        }
        let username = self.username.trim().to_owned();
        if username.is_empty() {
            self.form_error = Some("Enter a profile name.".to_owned());
            return;
        }
        if self.password.is_empty() {
            self.form_error = Some("Enter a password.".to_owned());
            return;
        }
        if self.password != self.confirm_password {
            self.form_error = Some("Passwords do not match.".to_owned());
            return;
        }

        let password = self.password.clone();
        self.form_error = None;
        self.clear_secrets();
        self.start_worker(VaultAction::Create { username, password });
    }

    fn submit_unlock(&mut self) {
        if !matches!(
            self.state,
            VaultState::Locked
                | VaultState::Failed {
                    operation: VaultOperation::Unlocking,
                    ..
                }
        ) {
            return;
        }
        if self.password.is_empty() {
            self.form_error = Some("Enter your password.".to_owned());
            return;
        }

        let password = self.password.clone();
        self.form_error = None;
        self.clear_secrets();
        self.start_worker(VaultAction::Unlock { password });
    }

    fn start_worker(&mut self, action: VaultAction) {
        let operation = match &action {
            VaultAction::Create { .. } => VaultOperation::Creating,
            VaultAction::Unlock { .. } => VaultOperation::Unlocking,
        };
        self.state = VaultState::Busy(operation);

        // A fresh channel per operation means a panicking worker disconnects
        // the receiver, which the UI reports as a failure instead of hanging.
        let (sender, receiver) = mpsc::channel();
        self.receiver = receiver;
        let vault = self.vault.clone();
        thread::spawn(move || {
            let result = match action {
                VaultAction::Create {
                    username,
                    mut password,
                } => {
                    let outcome = Identity::generate()
                        .map_err(StorageError::from)
                        .and_then(|identity| vault.create(&username, &password, &identity));
                    password.zeroize();
                    outcome
                }
                VaultAction::Unlock { mut password } => {
                    let outcome = vault.unlock(&password);
                    password.zeroize();
                    outcome
                }
            };
            let _ = sender.send(VaultOutcome { operation, result });
        });
    }

    fn poll_worker(&mut self) {
        if !matches!(self.state, VaultState::Busy(_)) {
            return;
        }
        match self.receiver.try_recv() {
            Ok(outcome) => match outcome.result {
                Ok(session) => {
                    let params = session.kdf_params();
                    let info = UnlockedInfo {
                        peer_id: session.identity().peer_id().to_string(),
                        fingerprint: session.identity().fingerprint().to_string(),
                        profile_id: session.profile_id_hex(),
                        kdf_summary: format!(
                            "Argon2id · {} MiB · t={} · p={}",
                            params.memory_kib / 1024,
                            params.iterations,
                            params.parallelism
                        ),
                    };
                    if let Err(error) = self.start_chat(&session) {
                        self.session = None;
                        self.chat_error = Some(error.clone());
                        self.state = VaultState::Failed {
                            operation: outcome.operation,
                            message: error,
                        };
                        self.form_error = None;
                        return;
                    }
                    self.session = Some(session);
                    self.state = VaultState::Unlocked(info);
                    self.form_error = None;
                }
                Err(error) => {
                    self.session = None;
                    self.state = VaultState::Failed {
                        operation: outcome.operation,
                        message: error.to_string(),
                    };
                }
            },
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                let operation = match self.state {
                    VaultState::Busy(operation) => operation,
                    _ => VaultOperation::Unlocking,
                };
                self.state = VaultState::Failed {
                    operation,
                    message: "Vault worker stopped unexpectedly".to_owned(),
                };
            }
        }
    }

    fn lock(&mut self) {
        self.session = None;
        self.chat = None;
        self.chat_error = None;
        self.peer_address.clear();
        self.contact_peer_id.clear();
        self.member_peer_id.clear();
        self.message_text.clear();
        self.state = if self.vault.exists() {
            VaultState::Locked
        } else {
            VaultState::Missing
        };
        self.form_error = None;
        self.clear_secrets();
    }

    fn clear_secrets(&mut self) {
        self.password.zeroize();
        self.confirm_password.zeroize();
        self.password.clear();
        self.confirm_password.clear();
        self.username.clear();
    }
}

fn short(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn vault_directory() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("p2p-messenger")
}

#[cfg(feature = "native")]
impl eframe::App for MessengerApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_without_chat(vault: Vault, receiver: mpsc::Receiver<VaultOutcome>) -> MessengerApp {
        MessengerApp {
            info: p2p_core::app_info(),
            vault,
            session: None,
            state: VaultState::Locked,
            receiver,
            chat: None,
            chat_error: None,
            peer_address: String::new(),
            contact_peer_id: String::new(),
            member_peer_id: String::new(),
            network_options: NetworkOptions::default(),
            message_text: String::new(),
            channel_name: String::new(),
            username: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            form_error: None,
            theme: Theme::Dark,
        }
    }

    fn empty_app() -> (tempfile::TempDir, MessengerApp) {
        let directory = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(directory.path()).expect("vault");
        let (_sender, receiver) = mpsc::channel();
        (directory, app_without_chat(vault, receiver))
    }

    #[test]
    fn attach_helper_rejects_missing_files_without_network_work() {
        let (_directory, mut app) = empty_app();
        app.send_file_path(&PathBuf::from("does-not-exist"));
        assert_eq!(app.chat_error.as_deref(), Some("Choose an existing file."));
    }

    #[test]
    fn attach_helper_fails_closed_without_an_active_conversation() {
        let (directory, mut app) = empty_app();
        let path = directory.path().join("note.txt");
        std::fs::write(&path, b"hello").expect("write local test file");
        app.send_file_path(&path);
        assert_eq!(
            app.chat_error.as_deref(),
            Some("No joined MLS conversation is active.")
        );
    }

    #[test]
    fn controller_start_failure_keeps_vault_failed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(directory.path()).expect("vault");
        let identity = Identity::generate().expect("identity");
        let mut session = vault
            .create("gui", "vault-password", &identity)
            .expect("vault session");
        session
            .store_mls_state(&[7u8; 16], "gui-test", b"gui-test", 0, b"value")
            .expect("orphan MLS group without application metadata");
        let (sender, receiver) = mpsc::channel();
        let mut app = MessengerApp {
            info: p2p_core::app_info(),
            vault,
            session: None,
            state: VaultState::Busy(VaultOperation::Unlocking),
            receiver,
            chat: None,
            chat_error: None,
            peer_address: String::new(),
            contact_peer_id: String::new(),
            member_peer_id: String::new(),
            network_options: NetworkOptions::default(),
            message_text: String::new(),
            channel_name: String::new(),
            username: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            form_error: None,
            theme: Theme::Dark,
        };
        sender
            .send(VaultOutcome {
                operation: VaultOperation::Unlocking,
                result: Ok(session),
            })
            .expect("send unlock outcome");

        app.poll_worker();

        assert!(matches!(
            app.state,
            VaultState::Failed {
                operation: VaultOperation::Unlocking,
                ..
            }
        ));
        assert!(app.chat.is_none());
        assert!(app.session.is_none());
        assert!(app.chat_error.is_some());
    }
}
