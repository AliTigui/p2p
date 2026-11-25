//! egui description of the native shell. No webview, DOM, Node, or npm.

#[cfg(feature = "native")]
use std::fs::{self, OpenOptions};
#[cfg(feature = "native")]
use std::io::Write;
#[cfg(all(unix, feature = "native"))]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(feature = "native")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use egui::{
    CentralPanel, Color32, Context, Id, Key, Layout, Panel, RichText, TextEdit, Ui, Visuals,
};
use p2p_chat::{
    MessengerController, PeerId, QuarantineDeletionPolicy, ReleaseApproval, TransferDirection,
    parse_address, parse_peer_id,
};
use p2p_core::AppInfo;
use p2p_identity::Identity;
use p2p_network::RelayMode;
use p2p_storage::{Session, StorageError, Vault};
#[cfg(feature = "native")]
use rfd::FileDialog;
use zeroize::Zeroize;

use crate::model::{
    MILESTONES, NetworkInfo, NetworkOptions, SECTIONS, Section, Theme, UnlockedInfo,
    VaultOperation, VaultState, filter_nav, next_theme, runtime_banner, security_rows,
};

const SEARCH_ID: &str = "p2p_messenger_search";
const ERROR_COLOR: Color32 = Color32::from_rgb(220, 120, 120);

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
    file_path: String,
    username: String,
    password: String,
    confirm_password: String,
    form_error: Option<String>,
    theme: Theme,
    search: String,
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
            file_path: String::new(),
            username: String::new(),
            password: String::new(),
            confirm_password: String::new(),
            form_error: None,
            theme: Theme::Dark,
            search: String::new(),
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
    fn start_chat(&mut self, session: &Session) {
        self.chat = None;
        self.chat_error = None;
        self.peer_address.clear();
        self.contact_peer_id.clear();
        self.member_peer_id.clear();
        self.message_text.clear();
        self.channel_name.clear();
        self.file_path.clear();
        let config = match self.network_options.to_config() {
            Ok(config) => config,
            Err(error) => {
                self.chat_error = Some(error);
                return;
            }
        };
        let storage = match session.try_clone() {
            Ok(storage) => storage,
            Err(error) => {
                self.chat_error = Some(error.to_string());
                return;
            }
        };
        match MessengerController::start_with_control_log(session.identity(), config, storage) {
            Ok(chat) => self.chat = Some(chat),
            Err(error) => self.chat_error = Some(error.to_string()),
        }
    }

    fn connect_peer(&mut self) {
        let address = match parse_address(&self.peer_address) {
            Ok(address) => address,
            Err(error) => {
                self.chat_error = Some(error.to_string());
                return;
            }
        };
        let Some(chat) = self.chat.as_mut() else {
            self.chat_error = Some("Network is not running".to_owned());
            return;
        };
        self.chat_error = None;
        self.peer_address.clear();
        if let Err(error) = chat.connect(address) {
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

    fn send_file(&mut self) {
        let path = PathBuf::from(self.file_path.trim());
        if path.as_os_str().is_empty() {
            self.chat_error = Some("Enter a local file path.".to_owned());
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
        match chat.send_file(peer, &path) {
            Ok(_) => {
                self.file_path.clear();
                self.chat_error = None;
            }
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
        let ctx = ui.ctx().clone();
        ctx.set_visuals(match self.theme {
            Theme::Dark => Visuals::dark(),
            Theme::Light => Visuals::light(),
        });

        self.handle_shortcuts(&ctx);
        self.poll_worker();
        self.poll_chat();

        let state = self.state.clone();
        let network_info = self.network_info();
        let unlocked = matches!(&state, VaultState::Unlocked(_));
        let banner = runtime_banner(&self.info, &state, network_info.as_ref());
        let active_conversation = self.chat.as_ref().and_then(|chat| chat.active_info());
        let security = security_rows(&state, network_info.as_ref(), active_conversation.as_ref());

        {
            Panel::top("top_bar").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("P2P Messenger");
                    ui.label(
                        RichText::new(banner)
                            .small()
                            .color(Color32::from_rgb(220, 160, 80)),
                    );
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        if unlocked && ui.button("Lock").clicked() {
                            self.lock();
                        }
                        let label = match self.theme {
                            Theme::Dark => "Light mode",
                            Theme::Light => "Dark mode",
                        };
                        if ui.button(label).clicked() {
                            self.theme = next_theme(self.theme);
                        }
                    });
                });
            });

            Panel::left("sidebar")
                .resizable(false)
                .default_size(250.0)
                .show(ui, |ui| {
                    ui.add(
                        TextEdit::singleline(&mut self.search)
                            .id(Id::new(SEARCH_ID))
                            .hint_text("Search (Ctrl/⌘+K)"),
                    );
                    ui.add_space(8.0);

                    let visible = filter_nav(&self.search);
                    for section in SECTIONS {
                        let items: Vec<_> = visible
                            .iter()
                            .filter(|item| item.section == section)
                            .collect();
                        if items.is_empty() {
                            continue;
                        }
                        ui.add_space(10.0);
                        ui.label(RichText::new(Section::label(section)).small().weak());
                        for item in items {
                            ui.add_enabled(false, egui::Button::new(item.label));
                        }
                    }

                    if visible.is_empty() {
                        ui.add_space(8.0);
                        ui.label(format!("No section matches “{}”.", self.search));
                    }
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(
                            "Navigation is a placeholder. Local vault controls are on the right.",
                        )
                        .small()
                        .weak(),
                    );
                });

            Panel::right("details")
                .resizable(false)
                .default_size(290.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("SECURITY & CONNECTION").small().weak());
                    ui.add_space(8.0);
                    for row in &security {
                        ui.label(RichText::new(row.label).small().weak());
                        ui.label(RichText::new(&row.value).small());
                        ui.separator();
                    }
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "Statuses reflect observed runtime state. Unimplemented features are shown as such.",
                        )
                        .small()
                        .weak(),
                    );
                });

            CentralPanel::default().show(ui, |ui| {
                ui.add_space(24.0);
                match &state {
                    VaultState::Missing
                    | VaultState::Failed {
                        operation: VaultOperation::Creating,
                        ..
                    } => self.render_create(ui),
                    VaultState::Busy(VaultOperation::Creating) => {
                        ui.heading("Creating your vault");
                        ui.add_space(8.0);
                        ui.spinner();
                        ui.label("Running Argon2id on a worker thread; the interface stays responsive.");
                    }
                    VaultState::Locked
                    | VaultState::Failed {
                        operation: VaultOperation::Unlocking,
                        ..
                    } => self.render_unlock(ui, &state),
                    VaultState::Busy(VaultOperation::Unlocking) => {
                        ui.heading("Unlocking your vault");
                        ui.add_space(8.0);
                        ui.spinner();
                        ui.label("Verifying your password on a worker thread; the interface stays responsive.");
                    }
                    VaultState::Unlocked(info) => self.render_unlocked(ui, info),
                }

                ui.add_space(18.0);
                ui.separator();
                ui.add_space(10.0);
                ui.label(RichText::new("IMPLEMENTATION ROADMAP").small().weak());
                ui.add_space(6.0);
                for milestone in MILESTONES {
                    ui.horizontal(|ui| {
                        ui.label(if milestone.done { "✓" } else { "·" });
                        if milestone.done {
                            ui.label(milestone.label);
                        } else {
                            ui.label(RichText::new(milestone.label).weak());
                        }
                    });
                }
            });
        }
    }

    fn render_create(&mut self, ui: &mut Ui) {
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
            ui.colored_label(ERROR_COLOR, format!("Last attempt failed: {message}"));
        } else {
            self.render_form_error(ui);
        }
        ui.add_space(10.0);
        if ui.button("Create vault").clicked() {
            self.submit_create();
        }
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Losing this password means permanent loss of the vault; no recovery is offered.",
            )
            .small()
            .weak(),
        );
    }

    fn render_unlock(&mut self, ui: &mut Ui, state: &VaultState) {
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
            ui.colored_label(ERROR_COLOR, format!("Last attempt failed: {message}"));
        } else {
            self.render_form_error(ui);
        }
        ui.add_space(10.0);
        if ui.button("Unlock").clicked() {
            self.submit_unlock();
        }
    }

    fn render_unlocked(&mut self, ui: &mut Ui, info: &UnlockedInfo) {
        ui.heading("Vault unlocked");
        ui.add_space(8.0);
        ui.label(format!("Profile: {}", info.profile_id));
        ui.label(format!("Peer ID: {}", info.peer_id));
        ui.label(format!("Fingerprint: {}", info.fingerprint));
        ui.label(format!("Key protection: {}", info.kdf_summary));

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("DIRECT CONNECTION").small().weak());
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
        ui.label("Peer address (must include /p2p/<peer-id>)");
        ui.add(
            TextEdit::singleline(&mut self.peer_address)
                .hint_text("/ip4/127.0.0.1/tcp/4001/p2p/12D3…"),
        );
        let (connect, disconnect) = ui
            .horizontal(|ui| {
                (
                    ui.button("Connect").clicked(),
                    ui.button("Disconnect all").clicked(),
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
                ui.label(
                    RichText::new("Automatic redial: no saved address")
                        .small()
                        .weak(),
                );
            } else {
                for peer in saved {
                    let short: String = peer.to_string().chars().take(12).collect();
                    ui.label(
                        RichText::new(format!(
                            "Redial {short}: {}",
                            chat.redial_state(&peer).description()
                        ))
                        .small()
                        .weak(),
                    );
                }
            }
        }
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "By default no bootstrap peers, DHT servers, or relays are configured. Direct dial requires an address you supply.",
            )
            .small()
            .weak(),
        );

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(
            RichText::new("OPTIONAL NETWORK CAPABILITIES")
                .small()
                .weak(),
        );
        ui.checkbox(
            &mut self.network_options.enable_identify,
            "Identify (bounded protocol metadata)",
        );
        ui.checkbox(
            &mut self.network_options.enable_ping,
            "Ping (low frequency)",
        );
        ui.checkbox(
            &mut self.network_options.enable_mdns,
            "mDNS local discovery (advisory only)",
        );
        ui.checkbox(
            &mut self.network_options.enable_kad,
            "Kademlia discovery (user-supplied bootstrap peers only)",
        );
        ui.checkbox(
            &mut self.network_options.enable_autonat,
            "AutoNAT best-effort status probe",
        );
        ui.checkbox(
            &mut self.network_options.enable_dcutr,
            "DCUtR hole punching when a relayed path exists",
        );
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
                        ui.selectable_value(&mut self.network_options.relay_mode, mode, label);
                    }
                });
        });
        ui.label(
            "Kademlia bootstrap addresses (one per line or comma-separated; /p2p/<peer-id> required)",
        );
        ui.add(TextEdit::multiline(
            &mut self.network_options.kad_bootstrap_peers,
        ));
        ui.label("Relay server addresses (client mode only; direct addresses required)");
        ui.add(TextEdit::multiline(&mut self.network_options.relay_servers));
        ui.label(
            RichText::new(
                "All optional capabilities are off and address lists are empty by default. \
                 Discovery candidates are advisory only: they are never auto-dialed, trusted, \
                 or treated as fingerprint-verified contacts. Relay operators can observe IPs, \
                 timing, and sizes and can deny service; file transfer over a relay is disabled. \
                 AutoNAT and DCUtR are best effort, not universal NAT traversal. There is no \
                 Tor/I2P/mixnet, anonymity, or metadata privacy claim. Settings apply when the \
                 network worker starts: lock and unlock the vault after changing them.",
            )
            .small()
            .weak(),
        );

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("MLS GROUPS").small().weak());

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
        if ui.button("Start encrypted chat").clicked() {
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
                ui.label(RichText::new("CHANNELS IN THIS MLS GROUP").small().weak());
                for channel in &active.channels {
                    let selected = active.active_channel == Some(channel.channel_id);
                    let marker = if selected { "● " } else { "   " };
                    let policy = if channel.acknowledged {
                        "policy acknowledged"
                    } else {
                        "policy awaiting receipts"
                    };
                    let label = format!(
                        "{marker}{} · rev {} · {} allowed · {policy}",
                        short(&channel.name, 20),
                        channel.revision,
                        channel.members.len()
                    );
                    if ui.button(label).clicked() {
                        self.select_channel(channel.channel_id);
                    }
                }
                ui.add(
                    TextEdit::singleline(&mut self.channel_name)
                        .hint_text("New channel name (admin only)"),
                );
                let idle = active.pending_operation.is_none();
                let can_create = idle && local_peer == Some(active.admin);
                if ui
                    .add_enabled(can_create, egui::Button::new("Create channel"))
                    .clicked()
                {
                    self.create_channel();
                }
                ui.label(
                    RichText::new(
                        "Channel metadata and text are MLS-encrypted application frames in one group. Channel membership is local client policy, not cryptographic access control.",
                    )
                    .small()
                    .weak(),
                );

                if ui
                    .add_enabled(idle, egui::Button::new("Refresh my MLS key"))
                    .clicked()
                {
                    self.update_member_key();
                }
                ui.label("Connected peer ID to add to this group");
                ui.add(
                    TextEdit::singleline(&mut self.member_peer_id)
                        .hint_text("12D3Koo… (must already be directly connected)"),
                );
                if ui
                    .add_enabled(idle, egui::Button::new("Add member"))
                    .clicked()
                {
                    self.add_member();
                }
                if let Some(local) = local_peer {
                    for member in &active.members {
                        if *member != local && *member != active.admin {
                            let label = format!("Remove {}", short(&member.to_string(), 14));
                            if ui.add_enabled(idle, egui::Button::new(label)).clicked() {
                                self.remove_member(*member);
                            }
                        }
                    }
                }
                ui.label(
                    RichText::new(
                        "Group changes are signed MLS commits. They stay pending until every required member acknowledges; messages and further changes are blocked while pending. Only the group admin can add, remove, or refresh keys.",
                    )
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
                ui.add(
                    TextEdit::singleline(&mut self.message_text)
                        .hint_text("Type a message for the selected channel"),
                );
                if ui.button("Send (MLS encrypted)").clicked() {
                    self.send_message();
                }
            }
            None => {
                ui.label("Start or join an MLS conversation before sending messages.");
            }
        }

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("ENCRYPTED FILE TRANSFER").small().weak());
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
                        if transfer.status.active() && ui.button("Abort transfer").clicked() {
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
                                && ui.button("Validate format / scan if configured").clicked()
                            {
                                self.scan_file(transfer.peer);
                            }
                            match transfer.approval {
                                ReleaseApproval::Pending => {
                                    if ui.button("Approve and store encrypted").clicked() {
                                        self.approve_and_release_file(transfer.peer);
                                    }
                                    if ui.button("Cancel release").clicked() {
                                        self.cancel_file(transfer.peer);
                                    }
                                }
                                ReleaseApproval::Approved => {
                                    if ui.button("Store encrypted in vault").clicked() {
                                        self.release_file(transfer.peer);
                                    }
                                    if ui.button("Cancel release").clicked() {
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
                            && ui.button("Delete quarantine ciphertext").clicked()
                        {
                            self.delete_file_quarantine(transfer.peer);
                        }
                    }
                });
        }
        ui.add_space(8.0);
        ui.label("Local file path for the active peer (maximum 64 MiB)");
        ui.add(TextEdit::singleline(&mut self.file_path).hint_text("/path/to/file.txt"));
        if ui.button("Send encrypted file").clicked() {
            self.send_file();
        }
        ui.label(
            RichText::new(
                "Incoming ciphertext is quarantined. Structural validation supports TXT, PNG, and GIF only; it is not malware detection. Integrity verification is not a scan, and scanning is unavailable without an independent scanner. Release requires a clean scanner result, a validated format, an allowed extension, and explicit per-file approval; released bytes are copied into the encrypted vault, never written as plaintext here. Quarantine ciphertext for a verified transfer is retained by default and is deleted only by an explicit request where policy permits; aborting an incomplete transfer removes its partial ciphertext. Active transfers have an inactivity timeout and can be aborted; release cancellation applies only after verification. Filesystem deletion is not secure erasure. This app configures no scanner or allowed extensions, so no release action appears by default.",
            )
            .small()
            .weak(),
        );

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(RichText::new("ENCRYPTED ATTACHMENTS").small().weak());
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
                            if ui.button("Save via OS dialog").clicked() {
                                self.save_attachment(item.id, &item.name);
                            }
                            if ui.button("Delete stored attachment").clicked() {
                                self.delete_attachment(item.id);
                            }
                        });
                    }
                });
        }
        ui.label(
            RichText::new(
                "Attachments are ciphertext at rest in the vault. The native OS save dialog is the only plaintext disk write and requires a path you choose; a cancelled dialog writes nothing.",
            )
            .small()
            .weak(),
        );
        #[cfg(not(feature = "native"))]
        ui.label(
            RichText::new("OS save dialog is available only in the native build.")
                .small()
                .weak(),
        );

        if let Some(error) = &self.chat_error {
            ui.colored_label(ERROR_COLOR, error);
        }
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "MLS group state and decrypted messages are memory-only. Receipts advance status only after verified MLS decryption; file chunks are encrypted and integrity-checked, but no malware scanner is configured.",
            )
            .small()
            .weak(),
        );
        ui.add_space(10.0);
        if ui.button("Lock vault").clicked() {
            self.lock();
        }
    }

    fn render_form_error(&self, ui: &mut Ui) {
        if let Some(error) = &self.form_error {
            ui.colored_label(ERROR_COLOR, error);
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
                    self.start_chat(&session);
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

    fn handle_shortcuts(&mut self, ctx: &Context) {
        let (focus_search, clear_search) = ctx.input(|input| {
            (
                input.modifiers.command_only() && input.key_pressed(Key::K),
                input.key_pressed(Key::Escape),
            )
        });

        if focus_search {
            ctx.memory_mut(|memory| memory.request_focus(Id::new(SEARCH_ID)));
        }
        if clear_search {
            self.search.clear();
        }
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
