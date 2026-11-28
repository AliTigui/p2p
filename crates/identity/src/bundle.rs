//! Complete local identity bundle with independent role keys.
//!
//! The bundle contains the libp2p transport keypair plus separate root, device,
//! MLS, application, and file Ed25519 keys. Its encoded form is private and must
//! only be written through the encrypted vault or password-encrypted export.

use std::fmt;

use libp2p_identity::{Keypair, ed25519};
use zeroize::{Zeroize, Zeroizing};

use crate::pq::PqSeed;
use crate::{
    DEFAULT_CERT_VALIDITY_SECONDS, IdentityCertificate, IdentityError, IdentityProof, IdentityRole,
    PqIdentityProof, PqSeeds, unix_time_seconds,
};

pub(crate) const BUNDLE_MAGIC: &[u8] = b"P2PMSGR-IDENTITY-BUNDLE";
const BUNDLE_VERSION: u8 = 2;
const LEGACY_BUNDLE_VERSION: u8 = 1;
const ROLE_KEY_LEN: usize = 64;
const MAX_TRANSPORT_KEY_BYTES: usize = 512;
/// Upper bound for one encoded identity bundle.
pub const MAX_IDENTITY_BUNDLE_BYTES: usize = 128 * 1024;

/// Private keys and public certificates for one local identity.
#[derive(Clone)]
pub(crate) struct IdentityBundle {
    transport: Keypair,
    root: ed25519::Keypair,
    device: ed25519::Keypair,
    mls: ed25519::Keypair,
    application: ed25519::Keypair,
    file: ed25519::Keypair,
    proof: IdentityProof,
    pq_seeds: PqSeeds,
    // Boxed so cloning/passing an `Identity` does not copy ~26 KiB of PQ
    // certificates and signatures onto every call frame.
    pq_proof: Box<PqIdentityProof>,
}

impl IdentityBundle {
    /// Generate a complete, freshly bound identity.
    pub(crate) fn generate() -> Result<Self, IdentityError> {
        Self::from_transport(Keypair::generate_ed25519())
    }

    /// Bind fresh role keys to an existing transport key. This is the legacy
    /// migration path for vaults that only stored the libp2p keypair.
    pub(crate) fn from_transport(transport: Keypair) -> Result<Self, IdentityError> {
        if transport.public().key_type() != libp2p_identity::KeyType::Ed25519 {
            return Err(IdentityError::NotEd25519);
        }
        let root = ed25519::Keypair::generate();
        let device = ed25519::Keypair::generate();
        let mls = ed25519::Keypair::generate();
        let application = ed25519::Keypair::generate();
        let file = ed25519::Keypair::generate();

        let mut device_id = [0u8; 16];
        getrandom::fill(&mut device_id).map_err(|_| IdentityError::Randomness)?;
        let now = unix_time_seconds();
        let expires = now.saturating_add(DEFAULT_CERT_VALIDITY_SECONDS);

        let root_cert = IdentityCertificate::new_signed(
            IdentityRole::Root,
            device_id,
            root.public().to_bytes(),
            now,
            expires,
            root.public().to_bytes(),
            &root,
        )?;
        let device_cert = IdentityCertificate::new_signed(
            IdentityRole::Device,
            device_id,
            device.public().to_bytes(),
            now,
            expires,
            root.public().to_bytes(),
            &root,
        )?;
        let transport_cert = IdentityCertificate::new_signed(
            IdentityRole::Transport,
            device_id,
            raw_transport_public_bytes(&transport)?,
            now,
            expires,
            device.public().to_bytes(),
            &device,
        )?;
        let mls_cert = IdentityCertificate::new_signed(
            IdentityRole::Mls,
            device_id,
            mls.public().to_bytes(),
            now,
            expires,
            device.public().to_bytes(),
            &device,
        )?;
        let application_cert = IdentityCertificate::new_signed(
            IdentityRole::Application,
            device_id,
            application.public().to_bytes(),
            now,
            expires,
            device.public().to_bytes(),
            &device,
        )?;
        let file_cert = IdentityCertificate::new_signed(
            IdentityRole::File,
            device_id,
            file.public().to_bytes(),
            now,
            expires,
            device.public().to_bytes(),
            &device,
        )?;
        let proof = IdentityProof::new(
            root.public().to_bytes(),
            root_cert,
            device_cert,
            transport_cert,
            mls_cert,
            application_cert,
            file_cert,
            Vec::new(),
        )?;
        proof.validate_at(now)?;

        let pq_seeds = PqSeeds::generate()?;
        let pq_proof = Box::new(PqIdentityProof::new(
            &transport.public().to_peer_id(),
            now,
            &pq_seeds,
        )?);
        pq_proof.validate_at(&transport.public().to_peer_id(), now)?;

        Ok(Self {
            transport,
            root,
            device,
            mls,
            application,
            file,
            proof,
            pq_seeds,
            pq_proof,
        })
    }

    pub(crate) fn proof(&self) -> &IdentityProof {
        &self.proof
    }

    pub(crate) fn pq_proof(&self) -> &PqIdentityProof {
        &self.pq_proof
    }

    pub(crate) fn pq_seeds(&self) -> &PqSeeds {
        &self.pq_seeds
    }

    pub(crate) fn pq_seed(&self, role: IdentityRole) -> Result<&PqSeed, IdentityError> {
        self.pq_seeds.get(role)
    }

    pub(crate) fn replace_pq_seed(
        &mut self,
        role: IdentityRole,
        seed: PqSeed,
        now: u64,
    ) -> Result<(), IdentityError> {
        self.pq_seeds.set(role, seed)?;
        *self.pq_proof =
            PqIdentityProof::new(&self.transport.public().to_peer_id(), now, &self.pq_seeds)?;
        self.pq_proof
            .validate_at(&self.transport.public().to_peer_id(), now)
    }

    pub(crate) fn transport(&self) -> &Keypair {
        &self.transport
    }

    pub(crate) fn root(&self) -> &ed25519::Keypair {
        &self.root
    }

    pub(crate) fn device(&self) -> &ed25519::Keypair {
        &self.device
    }

    pub(crate) fn role_key(&self, role: IdentityRole) -> Result<&ed25519::Keypair, IdentityError> {
        match role {
            IdentityRole::Root => Ok(&self.root),
            IdentityRole::Device => Ok(&self.device),
            IdentityRole::Mls => Ok(&self.mls),
            IdentityRole::Application => Ok(&self.application),
            IdentityRole::File => Ok(&self.file),
            IdentityRole::Transport => Err(IdentityError::WrongRole),
        }
    }

    pub(crate) fn set_root(&mut self, root: ed25519::Keypair) {
        self.root = root;
    }

    pub(crate) fn replace_proof(&mut self, proof: IdentityProof) {
        self.proof = proof;
    }

    pub(crate) fn validate_at(&self, now: u64) -> Result<(), IdentityError> {
        self.proof.validate_at(now)?;
        self.pq_proof
            .validate_at(&self.transport.public().to_peer_id(), now)?;
        let root = self.proof.root().public_key();
        let device = self.proof.device().public_key();
        if self.root.public().to_bytes() != root
            || self.device.public().to_bytes() != device
            || raw_transport_public_bytes(&self.transport)?
                != self.proof.role_public_key(IdentityRole::Transport)?
        {
            return Err(IdentityError::InvalidIdentityProof(
                "private role keys do not match their certificates".to_owned(),
            ));
        }
        for role in [
            IdentityRole::Mls,
            IdentityRole::Application,
            IdentityRole::File,
        ] {
            if self.role_key(role)?.public().to_bytes() != self.proof.role_public_key(role)? {
                return Err(IdentityError::InvalidIdentityProof(
                    "private role keys do not match their certificates".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Encode the complete private bundle. The returned buffer zeroizes itself.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let transport = Zeroizing::new(
            self.transport
                .to_protobuf_encoding()
                .map_err(|error| IdentityError::Crypto(error.to_string()))?,
        );
        if transport.len() > MAX_TRANSPORT_KEY_BYTES || transport.len() > u16::MAX as usize {
            return Err(IdentityError::InvalidEnvelope(
                "transport key encoding is too large".to_owned(),
            ));
        }
        let proof = self.proof.to_bytes();
        if proof.len() > u32::MAX as usize {
            return Err(IdentityError::InvalidEnvelope(
                "identity proof is too large".to_owned(),
            ));
        }
        let pq_proof = self.pq_proof.to_bytes();
        if pq_proof.len() > u32::MAX as usize {
            return Err(IdentityError::InvalidEnvelope(
                "PQ identity proof is too large".to_owned(),
            ));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            BUNDLE_MAGIC.len()
                + 1
                + 2
                + transport.len()
                + 5 * ROLE_KEY_LEN
                + 4
                + proof.len()
                + 5 * crate::PQ_SEED_BYTES
                + 4
                + pq_proof.len(),
        ));
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.push(BUNDLE_VERSION);
        bytes.extend_from_slice(&(transport.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&transport);
        for role in [
            IdentityRole::Root,
            IdentityRole::Device,
            IdentityRole::Mls,
            IdentityRole::Application,
            IdentityRole::File,
        ] {
            let mut key = Zeroizing::new(self.role_key(role)?.to_bytes());
            bytes.extend_from_slice(key.as_ref());
            key.zeroize();
        }
        bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&proof);
        for role in [
            IdentityRole::Root,
            IdentityRole::Device,
            IdentityRole::Mls,
            IdentityRole::Application,
            IdentityRole::File,
        ] {
            let mut seed = self.pq_seed(role)?.clone();
            bytes.extend_from_slice(seed.as_ref());
            seed.zeroize();
        }
        bytes.extend_from_slice(&(pq_proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&pq_proof);
        if bytes.len() > MAX_IDENTITY_BUNDLE_BYTES {
            return Err(IdentityError::InvalidEnvelope(
                "identity bundle is too large".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Parse a complete private bundle. Invalid private-key buffers zeroize as
    /// they are dropped.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_IDENTITY_BUNDLE_BYTES {
            return Err(IdentityError::InvalidEnvelope(
                "identity bundle is too large".to_owned(),
            ));
        }
        let header_len = BUNDLE_MAGIC.len() + 1 + 2;
        if bytes.len() < header_len + 5 * ROLE_KEY_LEN + 4 {
            return Err(IdentityError::InvalidEnvelope(
                "identity bundle is truncated".to_owned(),
            ));
        }
        if !bytes.starts_with(BUNDLE_MAGIC) {
            return Err(IdentityError::InvalidEnvelope(
                "identity bundle has the wrong magic".to_owned(),
            ));
        }
        let version = bytes[BUNDLE_MAGIC.len()];
        if version != BUNDLE_VERSION && version != LEGACY_BUNDLE_VERSION {
            return Err(IdentityError::InvalidEnvelope(
                "unsupported identity bundle version".to_owned(),
            ));
        }
        let mut position = BUNDLE_MAGIC.len() + 1;
        let transport_len = u16::from_le_bytes(
            bytes[position..position + 2]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        position += 2;
        if transport_len == 0 || transport_len > MAX_TRANSPORT_KEY_BYTES {
            return Err(IdentityError::InvalidEnvelope(
                "invalid transport key length".to_owned(),
            ));
        }
        let transport_end = position
            .checked_add(transport_len)
            .ok_or_else(|| IdentityError::InvalidEnvelope("invalid bundle offsets".to_owned()))?;
        let transport = Keypair::from_protobuf_encoding(
            bytes.get(position..transport_end).ok_or_else(|| {
                IdentityError::InvalidEnvelope("identity bundle is truncated".to_owned())
            })?,
        )
        .map_err(|_| IdentityError::InvalidEnvelope("transport key decode failed".to_owned()))?;
        position = transport_end;

        let mut role_keys = Vec::with_capacity(5);
        for _ in 0..5 {
            let mut encoded = Zeroizing::new([0u8; ROLE_KEY_LEN]);
            encoded.copy_from_slice(&bytes[position..position + ROLE_KEY_LEN]);
            position += ROLE_KEY_LEN;
            role_keys.push(
                ed25519::Keypair::try_from_bytes(&mut *encoded).map_err(|_| {
                    IdentityError::InvalidEnvelope("role key decode failed".to_owned())
                })?,
            );
        }
        let proof_len = u32::from_le_bytes(
            bytes[position..position + 4]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        position += 4;
        let proof_end = position
            .checked_add(proof_len)
            .ok_or_else(|| IdentityError::InvalidEnvelope("invalid bundle offsets".to_owned()))?;
        let proof =
            IdentityProof::from_bytes(bytes.get(position..proof_end).ok_or_else(|| {
                IdentityError::InvalidEnvelope("identity bundle is truncated".to_owned())
            })?)?;
        position = proof_end;

        let (pq_seeds, pq_proof) = if version == LEGACY_BUNDLE_VERSION {
            if position != bytes.len() {
                return Err(IdentityError::InvalidEnvelope(
                    "legacy identity bundle has trailing bytes".to_owned(),
                ));
            }
            let pq_seeds = PqSeeds::generate()?;
            let now = unix_time_seconds();
            let pq_proof = PqIdentityProof::new(&transport.public().to_peer_id(), now, &pq_seeds)?;
            pq_proof.validate_at(&transport.public().to_peer_id(), now)?;
            (pq_seeds, pq_proof)
        } else {
            let pq_seed_bytes = 5 * crate::PQ_SEED_BYTES;
            let pq_seed_end = position.checked_add(pq_seed_bytes).ok_or_else(|| {
                IdentityError::InvalidEnvelope("invalid bundle offsets".to_owned())
            })?;
            let pq_seed_slice = bytes.get(position..pq_seed_end).ok_or_else(|| {
                IdentityError::InvalidEnvelope("identity bundle is truncated".to_owned())
            })?;
            position = pq_seed_end;
            if bytes.len() < position + 4 {
                return Err(IdentityError::InvalidEnvelope(
                    "identity bundle is truncated".to_owned(),
                ));
            }
            let pq_proof_len = u32::from_le_bytes(
                bytes[position..position + 4]
                    .try_into()
                    .expect("fixed slice"),
            ) as usize;
            position += 4;
            let pq_proof_end = position.checked_add(pq_proof_len).ok_or_else(|| {
                IdentityError::InvalidEnvelope("invalid bundle offsets".to_owned())
            })?;
            if pq_proof_end != bytes.len() {
                return Err(IdentityError::InvalidEnvelope(
                    "identity bundle has trailing or missing bytes".to_owned(),
                ));
            }
            let pq_proof =
                PqIdentityProof::from_bytes(bytes.get(position..pq_proof_end).ok_or_else(
                    || IdentityError::InvalidEnvelope("identity bundle is truncated".to_owned()),
                )?)?;
            let seeds: Vec<_> = pq_seed_slice
                .chunks_exact(crate::PQ_SEED_BYTES)
                .map(|chunk| {
                    let mut seed = Zeroizing::new([0u8; crate::PQ_SEED_BYTES]);
                    seed.copy_from_slice(chunk);
                    seed
                })
                .collect();
            let pq_seeds = PqSeeds {
                root: seeds[0].clone(),
                device: seeds[1].clone(),
                mls: seeds[2].clone(),
                application: seeds[3].clone(),
                file: seeds[4].clone(),
            };
            pq_proof.validate_at(&transport.public().to_peer_id(), unix_time_seconds())?;
            (pq_seeds, pq_proof)
        };
        let pq_proof = Box::new(pq_proof);

        Ok(Self {
            transport,
            root: role_keys.remove(0),
            device: role_keys.remove(0),
            mls: role_keys.remove(0),
            application: role_keys.remove(0),
            file: role_keys.remove(0),
            proof,
            pq_seeds,
            pq_proof,
        })
    }
}

impl fmt::Debug for IdentityBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityBundle")
            .field("proof", self.proof())
            .field(
                "transport_peer_id",
                &self.transport.public().to_peer_id().to_string(),
            )
            .field("private_keys", &"<redacted>")
            .finish()
    }
}

/// A freshly generated root key for authenticated account rotation.
pub struct RootKey(ed25519::Keypair);

impl RootKey {
    /// Generate an independent root key.
    pub fn generate() -> Self {
        Self(ed25519::Keypair::generate())
    }

    /// Raw public key of the new root.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.public().to_bytes()
    }

    pub(crate) fn into_keypair(self) -> ed25519::Keypair {
        self.0
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey")
            .field("public", &crate::hex_short(&self.0.public().to_bytes()))
            .field("private", &"<redacted>")
            .finish()
    }
}

pub(crate) fn raw_transport_public_bytes(keypair: &Keypair) -> Result<[u8; 32], IdentityError> {
    let encoded = keypair.public().encode_protobuf();
    crate::raw_ed25519_public_bytes_from_protobuf(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RotationRecord;

    #[test]
    fn bundle_round_trip_preserves_all_role_keys() {
        let bundle = IdentityBundle::generate().expect("bundle");
        let encoded = bundle.encode().expect("encode");
        let decoded = IdentityBundle::decode(&encoded).expect("decode");
        decoded.validate_at(unix_time_seconds()).expect("validate");
        assert_eq!(decoded.transport().public(), bundle.transport().public());
        for role in IdentityRole::ALL {
            assert_eq!(
                IdentityCertificate::public_key(decoded.proof().certificate(role).expect("cert")),
                IdentityCertificate::public_key(bundle.proof().certificate(role).expect("cert")),
            );
        }
    }

    #[test]
    fn tampered_bundle_is_rejected() {
        let bundle = IdentityBundle::generate().expect("bundle");
        let encoded = bundle.encode().expect("encode");
        let mut tampered = encoded.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(IdentityBundle::decode(&tampered).is_err());
        assert!(IdentityBundle::decode(&[]).is_err());
    }

    #[test]
    fn encoded_bundle_does_not_expose_role_key_hex_in_debug() {
        let bundle = IdentityBundle::generate().expect("bundle");
        let debug = format!("{bundle:?}");
        let root = Zeroizing::new(bundle.root().to_bytes());
        let hex: String = root.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&hex));
    }

    #[test]
    fn legacy_transport_bundle_binds_fresh_distinct_roles() {
        let transport = Keypair::generate_ed25519();
        let expected_peer = transport.public().to_peer_id();
        let bundle = IdentityBundle::from_transport(transport).expect("legacy bundle");
        bundle.validate_at(unix_time_seconds()).expect("validate");
        assert_eq!(bundle.transport().public().to_peer_id(), expected_peer);
    }

    #[test]
    fn legacy_rotation_chain_records_are_supported() {
        let bundle = IdentityBundle::generate().expect("bundle");
        let old_root = bundle.proof().root().public_key();
        let next = RootKey::generate();
        let next_root = next.public_bytes();
        let record = RotationRecord::new(bundle.root(), &next.into_keypair(), unix_time_seconds())
            .expect("rotation");
        assert_eq!(record.previous_root(), old_root);
        assert_eq!(record.next_root(), next_root);
    }
}
