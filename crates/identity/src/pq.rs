//! ML-DSA-65 identity layer.
//!
//! The classical Ed25519 proof remains for the libp2p transport PeerId and for
//! legacy wire compatibility. This module carries a parallel, independent
//! post-quantum proof whose root, device, MLS, application, and file keys are
//! ML-DSA-65 keys. Every public key and signature is produced by the pinned
//! `ml-dsa` library; this module only defines a domain-separated container and
//! validation rules. The transport PeerId is signed into the PQ proof so a PQ
//! role key cannot be replayed under a different libp2p identity.

use std::fmt;

use libp2p_identity::PeerId;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Seed, Signature, SigningKey,
    VerifyingKey,
};
use zeroize::Zeroizing;

use crate::{DEFAULT_CERT_VALIDITY_SECONDS, IdentityError, IdentityRole};

/// OpenMLS/PQ signature code point for ML-DSA-65.
pub const PQ_SCHEME_ID: u16 = 0x0051;
/// Seed length shared by all ML-DSA parameter sets.
pub const PQ_SEED_BYTES: usize = 32;
/// Encoded ML-DSA-65 public key length.
pub const PQ_PUBLIC_KEY_BYTES: usize = 1952;
/// Encoded ML-DSA-65 signature length.
pub const PQ_SIGNATURE_BYTES: usize = 3309;
/// Version of the self-contained PQ proof container.
pub const PQ_PROOF_VERSION: u16 = 1;
/// Upper bound for one encoded PQ proof.
pub const MAX_PQ_IDENTITY_PROOF_BYTES: usize = 64 * 1024;

const PQ_PROOF_MAGIC: [u8; 4] = *b"PQP1";
const MAX_PEER_ID_BYTES: usize = 128;
const ROOT_DOMAIN: &[u8] = b"p2p-messenger/pq-proof/root/v1";
const DEVICE_DOMAIN: &[u8] = b"p2p-messenger/pq-proof/device/v1";
const ROLE_DOMAIN: &[u8] = b"p2p-messenger/pq-proof/role/v1";
const ROLE_SIGN_DOMAIN: &[u8] = b"p2p-messenger/pq-identity-sign/v1";

/// A 32-byte ML-DSA seed. The buffer zeroizes on drop.
pub(crate) type PqSeed = Zeroizing<[u8; PQ_SEED_BYTES]>;

/// Independent ML-DSA-65 seeds for every non-transport identity role.
#[derive(Clone)]
pub(crate) struct PqSeeds {
    pub(crate) root: PqSeed,
    pub(crate) device: PqSeed,
    pub(crate) mls: PqSeed,
    pub(crate) application: PqSeed,
    pub(crate) file: PqSeed,
}

pub(crate) fn random_seed() -> Result<PqSeed, IdentityError> {
    let mut seed = [0u8; PQ_SEED_BYTES];
    getrandom::fill(&mut seed).map_err(|_| IdentityError::Randomness)?;
    Ok(Zeroizing::new(seed))
}

impl PqSeeds {
    pub(crate) fn generate() -> Result<Self, IdentityError> {
        let mut root = [0u8; PQ_SEED_BYTES];
        let mut device = [0u8; PQ_SEED_BYTES];
        let mut mls = [0u8; PQ_SEED_BYTES];
        let mut application = [0u8; PQ_SEED_BYTES];
        let mut file = [0u8; PQ_SEED_BYTES];
        for seed in [
            &mut root,
            &mut device,
            &mut mls,
            &mut application,
            &mut file,
        ] {
            getrandom::fill(seed).map_err(|_| IdentityError::Randomness)?;
        }
        Ok(Self {
            root: Zeroizing::new(root),
            device: Zeroizing::new(device),
            mls: Zeroizing::new(mls),
            application: Zeroizing::new(application),
            file: Zeroizing::new(file),
        })
    }

    pub(crate) fn get(&self, role: IdentityRole) -> Result<&PqSeed, IdentityError> {
        match role {
            IdentityRole::Root => Ok(&self.root),
            IdentityRole::Device => Ok(&self.device),
            IdentityRole::Mls => Ok(&self.mls),
            IdentityRole::Application => Ok(&self.application),
            IdentityRole::File => Ok(&self.file),
            IdentityRole::Transport => Err(IdentityError::WrongRole),
        }
    }

    pub(crate) fn set(&mut self, role: IdentityRole, seed: PqSeed) -> Result<(), IdentityError> {
        match role {
            IdentityRole::Root => self.root = seed,
            IdentityRole::Device => self.device = seed,
            IdentityRole::Mls => self.mls = seed,
            IdentityRole::Application => self.application = seed,
            IdentityRole::File => self.file = seed,
            IdentityRole::Transport => return Err(IdentityError::WrongRole),
        }
        Ok(())
    }
}

impl fmt::Debug for PqSeeds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqSeeds")
            .field("private_seeds", &"<redacted>")
            .finish()
    }
}

/// A self-contained PQ identity proof. Public keys and signatures are fixed
/// size; only the authenticated transport PeerId is variable length.
#[derive(Clone)]
pub(crate) struct PqIdentityProof {
    issued_at: u64,
    expires_at: u64,
    peer_id_bytes: Vec<u8>,
    root: [u8; PQ_PUBLIC_KEY_BYTES],
    device: [u8; PQ_PUBLIC_KEY_BYTES],
    mls: [u8; PQ_PUBLIC_KEY_BYTES],
    application: [u8; PQ_PUBLIC_KEY_BYTES],
    file: [u8; PQ_PUBLIC_KEY_BYTES],
    root_signature: [u8; PQ_SIGNATURE_BYTES],
    device_signature: [u8; PQ_SIGNATURE_BYTES],
    mls_signature: [u8; PQ_SIGNATURE_BYTES],
    application_signature: [u8; PQ_SIGNATURE_BYTES],
    file_signature: [u8; PQ_SIGNATURE_BYTES],
}

impl PqIdentityProof {
    pub(crate) fn new(peer_id: &PeerId, now: u64, seeds: &PqSeeds) -> Result<Self, IdentityError> {
        let peer_id_bytes = peer_id.to_bytes();
        let root = public_key(&seeds.root)?;
        let device = public_key(&seeds.device)?;
        let mls = public_key(&seeds.mls)?;
        let application = public_key(&seeds.application)?;
        let file = public_key(&seeds.file)?;
        let expires_at = now.saturating_add(DEFAULT_CERT_VALIDITY_SECONDS);

        let root_signature = sign_seed(&seeds.root, &root_binding(&root, now, expires_at))?;
        let device_signature = sign_seed(
            &seeds.root,
            &device_binding(&device, &peer_id_bytes, now, expires_at),
        )?;
        let mls_signature = sign_seed(
            &seeds.device,
            &role_binding(IdentityRole::Mls, &mls, &peer_id_bytes, now, expires_at),
        )?;
        let application_signature = sign_seed(
            &seeds.device,
            &role_binding(
                IdentityRole::Application,
                &application,
                &peer_id_bytes,
                now,
                expires_at,
            ),
        )?;
        let file_signature = sign_seed(
            &seeds.device,
            &role_binding(IdentityRole::File, &file, &peer_id_bytes, now, expires_at),
        )?;

        Ok(Self {
            issued_at: now,
            expires_at,
            peer_id_bytes,
            root,
            device,
            mls,
            application,
            file,
            root_signature: fixed_signature(&root_signature)?,
            device_signature: fixed_signature(&device_signature)?,
            mls_signature: fixed_signature(&mls_signature)?,
            application_signature: fixed_signature(&application_signature)?,
            file_signature: fixed_signature(&file_signature)?,
        })
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_PQ_IDENTITY_PROOF_BYTES {
            return Err(IdentityError::InvalidIdentityProof(
                "PQ identity proof is too large".to_owned(),
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.fixed::<4>()? != PQ_PROOF_MAGIC {
            return Err(IdentityError::InvalidIdentityProof(
                "PQ identity proof has the wrong magic".to_owned(),
            ));
        }
        if reader.u16()? != PQ_PROOF_VERSION {
            return Err(IdentityError::InvalidIdentityProof(
                "unsupported PQ identity proof version".to_owned(),
            ));
        }
        if reader.u16()? != PQ_SCHEME_ID {
            return Err(IdentityError::InvalidIdentityProof(
                "unsupported PQ signature scheme".to_owned(),
            ));
        }
        let issued_at = reader.u64()?;
        let expires_at = reader.u64()?;
        if issued_at > expires_at {
            return Err(IdentityError::InvalidIdentityProof(
                "PQ identity proof validity window is invalid".to_owned(),
            ));
        }
        let peer_id_bytes = reader.var(MAX_PEER_ID_BYTES)?;
        let root = reader.fixed::<PQ_PUBLIC_KEY_BYTES>()?;
        let device = reader.fixed::<PQ_PUBLIC_KEY_BYTES>()?;
        let mls = reader.fixed::<PQ_PUBLIC_KEY_BYTES>()?;
        let application = reader.fixed::<PQ_PUBLIC_KEY_BYTES>()?;
        let file = reader.fixed::<PQ_PUBLIC_KEY_BYTES>()?;
        let root_signature = reader.fixed::<PQ_SIGNATURE_BYTES>()?;
        let device_signature = reader.fixed::<PQ_SIGNATURE_BYTES>()?;
        let mls_signature = reader.fixed::<PQ_SIGNATURE_BYTES>()?;
        let application_signature = reader.fixed::<PQ_SIGNATURE_BYTES>()?;
        let file_signature = reader.fixed::<PQ_SIGNATURE_BYTES>()?;
        reader.finish()?;
        Ok(Self {
            issued_at,
            expires_at,
            peer_id_bytes,
            root,
            device,
            mls,
            application,
            file,
            root_signature,
            device_signature,
            mls_signature,
            application_signature,
            file_signature,
        })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32_000);
        bytes.extend_from_slice(&PQ_PROOF_MAGIC);
        bytes.extend_from_slice(&PQ_PROOF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&PQ_SCHEME_ID.to_le_bytes());
        bytes.extend_from_slice(&self.issued_at.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        put_bytes(&mut bytes, &self.peer_id_bytes);
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.device);
        bytes.extend_from_slice(&self.mls);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.file);
        bytes.extend_from_slice(&self.root_signature);
        bytes.extend_from_slice(&self.device_signature);
        bytes.extend_from_slice(&self.mls_signature);
        bytes.extend_from_slice(&self.application_signature);
        bytes.extend_from_slice(&self.file_signature);
        bytes
    }

    pub(crate) fn validate_at(
        &self,
        expected_peer: &PeerId,
        now: u64,
    ) -> Result<(), IdentityError> {
        if now < self.issued_at || now > self.expires_at {
            return Err(IdentityError::ExpiredCertificate);
        }
        let peer = PeerId::from_bytes(&self.peer_id_bytes).map_err(|_| {
            IdentityError::InvalidIdentityProof("invalid PQ transport PeerId".to_owned())
        })?;
        if &peer != expected_peer {
            return Err(IdentityError::PeerIdMismatch);
        }
        if !verify_public(
            &self.root,
            &root_binding(&self.root, self.issued_at, self.expires_at),
            &self.root_signature,
        ) {
            return Err(IdentityError::InvalidIdentityProof(
                "PQ root certificate signature is invalid".to_owned(),
            ));
        }
        if !verify_public(
            &self.root,
            &device_binding(
                &self.device,
                &self.peer_id_bytes,
                self.issued_at,
                self.expires_at,
            ),
            &self.device_signature,
        ) {
            return Err(IdentityError::InvalidIdentityProof(
                "PQ device certificate signature is invalid".to_owned(),
            ));
        }
        for (role, key, signature) in [
            (IdentityRole::Mls, &self.mls, &self.mls_signature),
            (
                IdentityRole::Application,
                &self.application,
                &self.application_signature,
            ),
            (IdentityRole::File, &self.file, &self.file_signature),
        ] {
            let binding = role_binding(
                role,
                key,
                &self.peer_id_bytes,
                self.issued_at,
                self.expires_at,
            );
            if !verify_public(&self.device, &binding, signature) {
                return Err(IdentityError::InvalidIdentityProof(
                    "PQ role certificate signature is invalid".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn role_public_key(
        &self,
        role: IdentityRole,
    ) -> Result<[u8; PQ_PUBLIC_KEY_BYTES], IdentityError> {
        match role {
            IdentityRole::Root => Ok(self.root),
            IdentityRole::Device => Ok(self.device),
            IdentityRole::Mls => Ok(self.mls),
            IdentityRole::Application => Ok(self.application),
            IdentityRole::File => Ok(self.file),
            IdentityRole::Transport => Err(IdentityError::WrongRole),
        }
    }

    pub(crate) fn signing_bytes(
        &self,
        role: IdentityRole,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let mut bytes = signature_signing_bytes(role, message);
        bytes.extend_from_slice(&self.role_public_key(role)?);
        Ok(bytes)
    }

    pub(crate) fn verify_role_signature(
        &self,
        role: IdentityRole,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        let public = self.role_public_key(role)?;
        let bytes = self.signing_bytes(role, message)?;
        let signature: [u8; PQ_SIGNATURE_BYTES] = signature
            .try_into()
            .map_err(|_| IdentityError::InvalidSignature)?;
        if !verify_public(&public, &bytes, &signature) {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(())
    }
}

impl fmt::Debug for PqIdentityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqIdentityProof")
            .field("version", &PQ_PROOF_VERSION)
            .field("scheme", &PQ_SCHEME_ID)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("peer_id", &self.peer_id_bytes.len())
            .field("public_keys", &"<redacted>")
            .field("signatures", &"<redacted>")
            .finish()
    }
}

/// Domain-separated bytes signed by a PQ application role key. The certified
/// public key is appended so the signature is bound to one exact key.
pub(crate) fn signature_signing_bytes(role: IdentityRole, message: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ROLE_SIGN_DOMAIN.len() + 2 + message.len());
    bytes.extend_from_slice(ROLE_SIGN_DOMAIN);
    bytes.push(role.code());
    bytes.extend_from_slice(&(message.len() as u64).to_le_bytes());
    bytes.extend_from_slice(message);
    bytes
}

fn root_binding(public: &[u8; PQ_PUBLIC_KEY_BYTES], issued_at: u64, expires_at: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ROOT_DOMAIN.len() + 16 + PQ_PUBLIC_KEY_BYTES);
    bytes.extend_from_slice(ROOT_DOMAIN);
    bytes.extend_from_slice(&issued_at.to_le_bytes());
    bytes.extend_from_slice(&expires_at.to_le_bytes());
    bytes.extend_from_slice(public);
    bytes
}

fn device_binding(
    public: &[u8; PQ_PUBLIC_KEY_BYTES],
    peer_id_bytes: &[u8],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(DEVICE_DOMAIN.len() + 18 + PQ_PUBLIC_KEY_BYTES + peer_id_bytes.len());
    bytes.extend_from_slice(DEVICE_DOMAIN);
    bytes.extend_from_slice(&issued_at.to_le_bytes());
    bytes.extend_from_slice(&expires_at.to_le_bytes());
    put_bytes(&mut bytes, peer_id_bytes);
    bytes.extend_from_slice(public);
    bytes
}

fn role_binding(
    role: IdentityRole,
    public: &[u8; PQ_PUBLIC_KEY_BYTES],
    peer_id_bytes: &[u8],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(ROLE_DOMAIN.len() + 19 + PQ_PUBLIC_KEY_BYTES + peer_id_bytes.len());
    bytes.extend_from_slice(ROLE_DOMAIN);
    bytes.push(role.code());
    bytes.extend_from_slice(&issued_at.to_le_bytes());
    bytes.extend_from_slice(&expires_at.to_le_bytes());
    put_bytes(&mut bytes, peer_id_bytes);
    bytes.extend_from_slice(public);
    bytes
}

fn put_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    let len = u16::try_from(value.len()).expect("bounded proof field");
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value);
}

fn public_key(seed: &[u8; PQ_SEED_BYTES]) -> Result<[u8; PQ_PUBLIC_KEY_BYTES], IdentityError> {
    let seed: &Seed = seed
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Crypto("invalid ML-DSA seed".to_owned()))?;
    let encoded = SigningKey::<MlDsa65>::from_seed(seed)
        .verifying_key()
        .encode();
    let mut public = [0u8; PQ_PUBLIC_KEY_BYTES];
    public.copy_from_slice(&encoded);
    Ok(public)
}

pub(crate) fn sign_seed(
    seed: &[u8; PQ_SEED_BYTES],
    message: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let seed: &Seed = seed
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Crypto("invalid ML-DSA seed".to_owned()))?;
    let signature = SigningKey::<MlDsa65>::from_seed(seed)
        .expanded_key()
        .sign_deterministic(message, &[])
        .map_err(|_| IdentityError::Crypto("ML-DSA signing failed".to_owned()))?;
    Ok(signature.encode().to_vec())
}

fn fixed_signature(signature: &[u8]) -> Result<[u8; PQ_SIGNATURE_BYTES], IdentityError> {
    signature
        .try_into()
        .map_err(|_| IdentityError::Crypto("unexpected ML-DSA signature length".to_owned()))
}

fn verify_public(
    public: &[u8; PQ_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; PQ_SIGNATURE_BYTES],
) -> bool {
    let Ok(encoded_public) = EncodedVerifyingKey::<MlDsa65>::try_from(public.as_slice()) else {
        return false;
    };
    let public_key = VerifyingKey::<MlDsa65>::decode(&encoded_public);
    let Ok(encoded_signature) = EncodedSignature::<MlDsa65>::try_from(signature.as_slice()) else {
        return false;
    };
    let Some(decoded_signature) = Signature::<MlDsa65>::decode(&encoded_signature) else {
        return false;
    };
    public_key.verify_with_context(message, &[], &decoded_signature)
}

/// Verify an ML-DSA-65 role signature against an already pinned raw verifying
/// key. Unlike proof-based verification, this function does not trust a
/// self-contained proof or the classical PeerId contained in it; the caller
/// must have obtained `public_key` from a local trust anchor.
pub fn verify_pq_role_signature_with_key(
    role: IdentityRole,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    if role == IdentityRole::Transport {
        return Err(IdentityError::WrongRole);
    }
    let public: [u8; PQ_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| IdentityError::Crypto("unexpected ML-DSA public key length".to_owned()))?;
    let signature = fixed_signature(signature)?;
    let mut bytes = signature_signing_bytes(role, message);
    bytes.extend_from_slice(&public);
    if verify_public(&public, &bytes, &signature) {
        Ok(())
    } else {
        Err(IdentityError::InvalidSignature)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn u16(&mut self) -> Result<u16, IdentityError> {
        let bytes = self.fixed::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, IdentityError> {
        let bytes = self.fixed::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn take(&mut self, len: usize) -> Result<Vec<u8>, IdentityError> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            IdentityError::InvalidIdentityProof("invalid PQ identity proof offsets".to_owned())
        })?;
        let slice = self.bytes.get(self.position..end).ok_or_else(|| {
            IdentityError::InvalidIdentityProof("PQ identity proof is truncated".to_owned())
        })?;
        self.position = end;
        Ok(slice.to_vec())
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], IdentityError> {
        let bytes = self.take(N)?;
        let mut output = [0u8; N];
        output.copy_from_slice(&bytes);
        Ok(output)
    }

    fn var(&mut self, max: usize) -> Result<Vec<u8>, IdentityError> {
        let len = usize::from(self.u16()?);
        if len > max || len == 0 {
            return Err(IdentityError::InvalidIdentityProof(
                "invalid PQ identity proof field length".to_owned(),
            ));
        }
        self.take(len)
    }

    fn finish(self) -> Result<(), IdentityError> {
        if self.position != self.bytes.len() {
            return Err(IdentityError::InvalidIdentityProof(
                "PQ identity proof has trailing bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> (PeerId, PqSeeds, PqIdentityProof) {
        let keypair = libp2p_identity::Keypair::generate_ed25519();
        let peer = keypair.public().to_peer_id();
        let seeds = PqSeeds::generate().expect("PQ seeds");
        let proof = PqIdentityProof::new(&peer, 1_000, &seeds).expect("PQ proof");
        (peer, seeds, proof)
    }

    #[test]
    fn pq_proof_round_trips_and_verifies() {
        let (peer, _, proof) = identity();
        let bytes = proof.to_bytes();
        let decoded = PqIdentityProof::from_bytes(&bytes).expect("decode");
        decoded.validate_at(&peer, 1_001).expect("valid proof");
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn pq_proof_rejects_wrong_peer_tampering_and_expiry() {
        let (peer, _, proof) = identity();
        let other = libp2p_identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(proof.validate_at(&other, 1_001).is_err());
        assert!(proof.validate_at(&peer, 9_000_000_000).is_err());

        let mut bytes = proof.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let decoded = PqIdentityProof::from_bytes(&bytes).expect("decode tampered proof");
        assert!(decoded.validate_at(&peer, 1_001).is_err());
    }

    #[test]
    fn pq_signatures_are_role_bound() {
        let (peer, seeds, proof) = identity();
        let message = b"p2p-messenger test message";
        let signed = proof
            .signing_bytes(IdentityRole::Application, message)
            .expect("signing bytes");
        let signature =
            sign_seed(seeds.get(IdentityRole::Application).expect("seed"), &signed).expect("sign");
        proof
            .validate_at(&peer, 1_001)
            .expect("proof validates before signature check");
        proof
            .verify_role_signature(IdentityRole::Application, message, &signature)
            .expect("application signature");
        let pinned = proof
            .role_public_key(IdentityRole::Application)
            .expect("application key");
        verify_pq_role_signature_with_key(IdentityRole::Application, &pinned, message, &signature)
            .expect("pinned application signature");
        assert!(
            verify_pq_role_signature_with_key(IdentityRole::File, &pinned, message, &signature)
                .is_err()
        );
        assert!(
            proof
                .verify_role_signature(IdentityRole::File, message, &signature)
                .is_err()
        );
    }
}
