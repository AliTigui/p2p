# ADR-0003: Password wraps a random master key with domain-separated subkeys

- Status: Accepted
- Date: 2026-11-23

## Context
Local data must be encrypted at rest, the user must authenticate locally with a password, and password changes must not require re-encrypting all stored data.

## Decision
Generate a random 32-byte master key. Derive a KEK from the password with Argon2id (96 MiB, t=4, p=1, 16-byte salt) and use XChaCha20-Poly1305 to wrap the master key in a versioned envelope with domain-separated AAD. Derive independent subkeys via HKDF-SHA256 for database, identity, attachments, search index, and backup. A password change creates a new salt/KEK, upgrades weak stored parameters without downgrading stronger ones, and re-wraps only the master key. Existing weak vaults are rewrapped on the first successful unlock. This is at-rest hardening only and does not protect a fully compromised endpoint with access to decrypted memory.

## Consequences
- Password changes are cheap and safe.
- Compromise of one subkey does not reveal others.
- Losing password and backup material means permanent data loss; no recovery promise is made.
- Argon2id parameters are stored in the envelope and can be migrated when a profile is next unlocked.
