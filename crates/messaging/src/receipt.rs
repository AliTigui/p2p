//! Canonical application receipt encoding.
//!
//! This is the cleartext application body that `p2p-groups` encrypts before it
//! is placed in an envelope payload. The codec alone is not a confidentiality
//! or transport-security mechanism; MLS ciphertext provides that protection.

use crate::MessageError;

const RECEIPT_VERSION: u8 = 1;
const DELIVERED: u8 = 1;
const READ: u8 = 2;
const RECEIPT_LEN: usize = 1 + 1 + 16;

/// Explicit acknowledgement state for an outgoing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    Delivered,
    Read,
}

impl ReceiptStatus {
    fn code(self) -> u8 {
        match self {
            Self::Delivered => DELIVERED,
            Self::Read => READ,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            DELIVERED => Some(Self::Delivered),
            READ => Some(Self::Read),
            _ => None,
        }
    }
}

/// A signed receipt body. `message_id` refers to the original envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub status: ReceiptStatus,
    pub message_id: [u8; 16],
}

impl Receipt {
    pub fn new(status: ReceiptStatus, message_id: [u8; 16]) -> Self {
        Self { status, message_id }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_LEN);
        bytes.push(RECEIPT_VERSION);
        bytes.push(self.status.code());
        bytes.extend_from_slice(&self.message_id);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() != RECEIPT_LEN || bytes[0] != RECEIPT_VERSION {
            return Err(MessageError::InvalidReceipt);
        }
        let status = ReceiptStatus::from_code(bytes[1]).ok_or(MessageError::InvalidReceipt)?;
        let message_id: [u8; 16] = bytes[2..]
            .try_into()
            .map_err(|_| MessageError::InvalidReceipt)?;
        Ok(Self { status, message_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_round_trip() {
        let receipt = Receipt::new(ReceiptStatus::Read, [4u8; 16]);
        assert_eq!(
            Receipt::from_bytes(&receipt.to_bytes()).expect("decoded receipt"),
            receipt
        );
    }

    #[test]
    fn malformed_receipts_fail() {
        assert!(Receipt::from_bytes(&[]).is_err());
        let mut bytes = Receipt::new(ReceiptStatus::Delivered, [1u8; 16]).to_bytes();
        bytes[1] = 99;
        assert!(matches!(
            Receipt::from_bytes(&bytes),
            Err(MessageError::InvalidReceipt)
        ));
        bytes.push(0);
        assert!(Receipt::from_bytes(&bytes).is_err());
    }
}
