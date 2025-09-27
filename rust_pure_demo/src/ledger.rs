use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Public API for generating an Ed25519 keypair encoded in base64 so that
/// the binary can easily print and reuse it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keypair {
    pub public_key: String,
    pub secret_key: String,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key = general_purpose::STANDARD.encode(verifying_key.to_bytes());
        let secret_key = general_purpose::STANDARD.encode(signing_key.to_bytes());
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey, LedgerError> {
        decode_signing_key(&self.secret_key)
    }

    pub fn from_secret(secret_key_b64: &str) -> Result<Self, LedgerError> {
        let signing_key = decode_signing_key(secret_key_b64)?;
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            public_key: general_purpose::STANDARD.encode(verifying_key.to_bytes()),
            secret_key: secret_key_b64.to_owned(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendRequest {
    pub payload: String,
    pub public_key: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub index: u64,
    pub timestamp: u64,
    pub payload: String,
    pub prev_hash: String,
    pub hash: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct Ledger {
    entries: Vec<LedgerEntry>,
    path: PathBuf,
}

impl Ledger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| LedgerError::Io(path.clone(), err))?;
            }
            // Ensure the file exists so later we can append to it safely.
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(&path)
                .map_err(|err| LedgerError::Io(path.clone(), err))?;
            return Ok(Self {
                entries: Vec::new(),
                path,
            });
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|err| LedgerError::Io(path.clone(), err))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|err| LedgerError::Io(path.clone(), err))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: LedgerEntry =
                serde_json::from_str(&line).map_err(|err| LedgerError::Serde(line.clone(), err))?;
            Self::validate_entry(&entries, &entry)?;
            entries.push(entry);
        }

        Ok(Self { entries, path })
    }

    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    pub fn signable_content(&self, payload: impl Into<String>, timestamp: u64) -> SignableContent {
        let payload = payload.into();
        let index = self
            .entries
            .last()
            .map(|entry| entry.index + 1)
            .unwrap_or(0);
        let prev_hash = self
            .entries
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| String::from("GENESIS"));
        SignableContent {
            index,
            prev_hash,
            timestamp,
            payload,
        }
    }

    pub fn prepare_append(
        &self,
        payload: impl Into<String>,
        secret_key_b64: &str,
        timestamp: u64,
    ) -> Result<AppendRequest, LedgerError> {
        let payload = payload.into();
        let signable = self.signable_content(payload.clone(), timestamp);
        let signing_key = decode_signing_key(secret_key_b64)?;
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(&signable.message());
        Ok(AppendRequest {
            payload,
            public_key: general_purpose::STANDARD.encode(verifying_key.to_bytes()),
            signature: general_purpose::STANDARD.encode(signature.to_bytes()),
            timestamp,
        })
    }

    pub fn append(&mut self, request: AppendRequest) -> Result<&LedgerEntry, LedgerError> {
        let index = self
            .entries
            .last()
            .map(|entry| entry.index + 1)
            .unwrap_or(0);
        let prev_hash = self
            .entries
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| String::from("GENESIS"));
        if let Some(last) = self.entries.last() {
            if request.timestamp < last.timestamp {
                return Err(LedgerError::TimestampRegression {
                    previous: last.timestamp,
                    candidate: request.timestamp,
                });
            }
        }

        let signing_bytes = signing_bytes(
            index,
            request.timestamp,
            &prev_hash,
            request.payload.as_bytes(),
        );
        verify_signature(&signing_bytes, &request.public_key, &request.signature)?;

        let hash = compute_hash(
            index,
            request.timestamp,
            &request.payload,
            &prev_hash,
            &request.public_key,
            &request.signature,
        );

        let entry = LedgerEntry {
            index,
            timestamp: request.timestamp,
            payload: request.payload,
            prev_hash,
            hash,
            public_key: request.public_key,
            signature: request.signature,
        };

        self.persist_entry(&entry)?;
        self.entries.push(entry);
        Ok(self.entries.last().expect("entry just pushed"))
    }

    fn persist_entry(&self, entry: &LedgerEntry) -> Result<(), LedgerError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| LedgerError::Io(self.path.clone(), err))?;
        let line = serde_json::to_string(entry)
            .map_err(|err| LedgerError::Serde(format!("entry {}", entry.index), err))?;
        file.write_all(line.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|err| LedgerError::Io(self.path.clone(), err))
    }

    fn validate_entry(
        prev_entries: &[LedgerEntry],
        entry: &LedgerEntry,
    ) -> Result<(), LedgerError> {
        let expected_index = prev_entries.last().map(|prev| prev.index + 1).unwrap_or(0);
        if entry.index != expected_index {
            return Err(LedgerError::IndexMismatch {
                expected: expected_index,
                found: entry.index,
            });
        }

        let expected_prev_hash = prev_entries
            .last()
            .map(|prev| prev.hash.clone())
            .unwrap_or_else(|| String::from("GENESIS"));
        if entry.prev_hash != expected_prev_hash {
            return Err(LedgerError::PrevHashMismatch {
                expected: expected_prev_hash,
                found: entry.prev_hash.clone(),
            });
        }

        let signing_bytes = signing_bytes(
            entry.index,
            entry.timestamp,
            &entry.prev_hash,
            entry.payload.as_bytes(),
        );
        verify_signature(&signing_bytes, &entry.public_key, &entry.signature)?;

        let expected_hash = compute_hash(
            entry.index,
            entry.timestamp,
            &entry.payload,
            &entry.prev_hash,
            &entry.public_key,
            &entry.signature,
        );
        if entry.hash != expected_hash {
            return Err(LedgerError::HashMismatch {
                expected: expected_hash,
                found: entry.hash.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SignableContent {
    pub index: u64,
    pub prev_hash: String,
    pub timestamp: u64,
    pub payload: String,
}

impl SignableContent {
    pub fn message(&self) -> Vec<u8> {
        signing_bytes(
            self.index,
            self.timestamp,
            &self.prev_hash,
            self.payload.as_bytes(),
        )
    }
}

fn signing_bytes(index: u64, timestamp: u64, prev_hash: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 8 + prev_hash.len() + payload.len());
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(prev_hash.as_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn decode_signing_key(secret_key_b64: &str) -> Result<SigningKey, LedgerError> {
    let secret_bytes = general_purpose::STANDARD
        .decode(secret_key_b64)
        .map_err(LedgerError::Base64Decode)?;
    let secret_array: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| LedgerError::InvalidSecretKeyLength(bytes.len()))?;
    Ok(SigningKey::from_bytes(&secret_array))
}

fn compute_hash(
    index: u64,
    timestamp: u64,
    payload: &str,
    prev_hash: &str,
    public_key: &str,
    signature: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(payload.as_bytes());
    hasher.update(public_key.as_bytes());
    hasher.update(signature.as_bytes());
    hex::encode(hasher.finalize())
}

fn verify_signature(
    message: &[u8],
    public_key_b64: &str,
    signature_b64: &str,
) -> Result<(), LedgerError> {
    let public_bytes = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(LedgerError::Base64Decode)?;
    let public_array: [u8; 32] = public_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| LedgerError::InvalidPublicKeyLength(bytes.len()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_array).map_err(|_| LedgerError::InvalidPublicKey)?;

    let signature_bytes = general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(LedgerError::Base64Decode)?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| LedgerError::InvalidSignatureLength(bytes.len()))?;
    let signature = Signature::from_bytes(&signature_array);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| LedgerError::SignatureVerificationFailed)
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("I/O error accessing {0:?}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("failed to decode base64: {0}")]
    Base64Decode(#[source] base64::DecodeError),
    #[error("invalid public key length: {0} bytes")]
    InvalidPublicKeyLength(usize),
    #[error("invalid secret key length: {0} bytes")]
    InvalidSecretKeyLength(usize),
    #[error("invalid signature length: {0} bytes")]
    InvalidSignatureLength(usize),
    #[error("public key material rejected")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("serde error while processing `{0}`: {1}")]
    Serde(String, #[source] serde_json::Error),
    #[error("hash mismatch: expected {expected}, found {found}")]
    HashMismatch { expected: String, found: String },
    #[error("prev_hash mismatch: expected {expected}, found {found}")]
    PrevHashMismatch { expected: String, found: String },
    #[error("index mismatch: expected {expected}, found {found}")]
    IndexMismatch { expected: u64, found: u64 },
    #[error("timestamp {candidate} regressed after {previous}")]
    TimestampRegression { previous: u64, candidate: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn append_and_reload_roundtrip() {
        let file = NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        drop(file);

        let keypair = Keypair::generate();
        let mut ledger = Ledger::open(&path).expect("open empty ledger");
        let payload = "hello world".to_string();
        let timestamp = 1;
        let request = ledger
            .prepare_append(payload.clone(), &keypair.secret_key, timestamp)
            .expect("prepare append");
        ledger.append(request).expect("append succeeds");

        drop(ledger);

        let ledger = Ledger::open(&path).expect("reopen ledger");
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].payload, payload);
    }
}
