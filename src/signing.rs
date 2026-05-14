//! Checksum, signing, and verification metadata contracts.

use crate::{
    validate_redaction, validate_release_label, DataClass, RedactionState, ReleaseError,
    ReleaseResult, ReleaseRights, TraceContext,
};

/// Signing metadata schema emitted by this crate version.
pub const SIGNING_SCHEMA_VERSION: &str = "alani.release.signing.v1";
/// Fixed digest length used by release checksums.
pub const DIGEST_LEN: usize = 32;
/// Maximum key identifier length.
pub const MAX_KEY_ID_LEN: usize = 128;
/// Maximum signature byte length represented by this skeleton.
pub const MAX_SIGNATURE_BYTES: usize = 512;
/// Maximum signer owner label length.
pub const MAX_SIGNER_LABEL_LEN: usize = 128;

/// Release checksum bytes.
pub type ReleaseDigest = [u8; DIGEST_LEN];

/// Checksum algorithm identifier.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumAlgorithm {
    /// SHA-256 digest bytes.
    Sha256 = 0,
    /// BLAKE3 fixture digest bytes for host-mode tests.
    Blake3Fixture = 1,
}

/// Signature algorithm identifier.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// Ed25519 release signature.
    Ed25519 = 0,
    /// RSA-PSS SHA-256 release signature.
    RsaPssSha256 = 1,
    /// Host-mode fixture signature.
    Fixture = 2,
}

/// Signature lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureState {
    /// No signature metadata is present.
    Unsigned = 0,
    /// Host-mode fixture signature is present.
    FixtureSigned = 1,
    /// Release signature is present.
    Signed = 2,
    /// Signature was revoked.
    Revoked = 3,
    /// Verification failed.
    VerificationFailed = 4,
}

impl SignatureState {
    /// Returns `true` when the state is acceptable for release publication.
    pub const fn is_accepted(self, allow_fixture: bool) -> bool {
        matches!(self, Self::Signed) || (allow_fixture && matches!(self, Self::FixtureSigned))
    }
}

/// Verification outcome.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    /// Verification has not run.
    Unknown = 0,
    /// Verification succeeded.
    Verified = 1,
    /// Verification failed.
    Failed = 2,
    /// Signing key expired.
    Expired = 3,
    /// Signing key or signature was revoked.
    Revoked = 4,
}

/// Signing policy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignaturePolicy {
    /// Whether a signature is required.
    pub require_signature: bool,
    /// Whether fixture signatures are accepted.
    pub allow_fixture: bool,
    /// Whether digest bytes must be nonzero.
    pub require_nonzero_digest: bool,
    /// Maximum signature byte length.
    pub max_signature_bytes: usize,
}

impl SignaturePolicy {
    /// Default release-like policy.
    pub const DEFAULT: Self = Self {
        require_signature: true,
        allow_fixture: false,
        require_nonzero_digest: true,
        max_signature_bytes: MAX_SIGNATURE_BYTES,
    };

    /// Host-mode fixture policy.
    pub const HOST_FIXTURE: Self = Self {
        require_signature: true,
        allow_fixture: true,
        require_nonzero_digest: true,
        max_signature_bytes: MAX_SIGNATURE_BYTES,
    };

    /// Validates policy metadata.
    pub const fn validate(self) -> ReleaseResult<()> {
        if self.max_signature_bytes == 0 || self.max_signature_bytes > MAX_SIGNATURE_BYTES {
            Err(ReleaseError::InvalidSignature)
        } else {
            Ok(())
        }
    }
}

impl Default for SignaturePolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Signing key metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningKey<'a> {
    /// Key identifier.
    pub key_id: &'a str,
    /// Signature algorithm.
    pub algorithm: SignatureAlgorithm,
    /// Owner or release authority label.
    pub owner: &'a str,
    /// Expiration counter supplied by release tooling; zero means unspecified.
    pub expires_at_counter: u64,
    /// Whether the key is revoked.
    pub revoked: bool,
    /// Key metadata classification.
    pub data_class: DataClass,
    /// Key metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> SigningKey<'a> {
    /// Creates signing key metadata.
    pub const fn new(key_id: &'a str, algorithm: SignatureAlgorithm, owner: &'a str) -> Self {
        Self {
            key_id,
            algorithm,
            owner,
            expires_at_counter: 0,
            revoked: false,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Sets expiration counter.
    pub const fn with_expiration(mut self, expires_at_counter: u64) -> Self {
        self.expires_at_counter = expires_at_counter;
        self
    }

    /// Marks the key revoked or active.
    pub const fn revoked(mut self, revoked: bool) -> Self {
        self.revoked = revoked;
        self
    }

    /// Sets classification and redaction state.
    pub const fn classified(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Validates signing key metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.key_id, MAX_KEY_ID_LEN)?;
        validate_release_label(self.owner, MAX_SIGNER_LABEL_LEN)?;
        if self.revoked {
            return Err(ReleaseError::InvalidSignature);
        }
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Signature proof metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProof<'a> {
    /// Signing key metadata.
    pub key: SigningKey<'a>,
    /// Signature algorithm.
    pub algorithm: SignatureAlgorithm,
    /// Signature bytes or fixture marker bytes.
    pub signature_bytes: &'a [u8],
    /// Signature state.
    pub state: SignatureState,
    /// Signing counter supplied by release tooling.
    pub signed_counter: u64,
    /// Verification status.
    pub verification: VerificationStatus,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> SignatureProof<'a> {
    /// Creates signature proof metadata.
    pub const fn new(
        key: SigningKey<'a>,
        signature_bytes: &'a [u8],
        state: SignatureState,
    ) -> Self {
        Self {
            key,
            algorithm: key.algorithm,
            signature_bytes,
            state,
            signed_counter: 0,
            verification: VerificationStatus::Unknown,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets signing counter.
    pub const fn with_signed_counter(mut self, signed_counter: u64) -> Self {
        self.signed_counter = signed_counter;
        self
    }

    /// Sets verification status.
    pub const fn with_verification(mut self, verification: VerificationStatus) -> Self {
        self.verification = verification;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates proof metadata under policy.
    pub fn validate(self, policy: SignaturePolicy) -> ReleaseResult<()> {
        policy.validate()?;
        self.key.validate()?;
        if self.algorithm != self.key.algorithm {
            return Err(ReleaseError::InvalidSignature);
        }
        if self.signature_bytes.is_empty() {
            return Err(ReleaseError::SignatureRequired);
        }
        if self.signature_bytes.len() > policy.max_signature_bytes {
            return Err(ReleaseError::FieldTooLong);
        }
        if self.signed_counter == 0 {
            return Err(ReleaseError::InvalidSignature);
        }
        if !self.state.is_accepted(policy.allow_fixture) {
            return Err(ReleaseError::SignatureRequired);
        }
        if matches!(
            self.verification,
            VerificationStatus::Failed | VerificationStatus::Expired | VerificationStatus::Revoked
        ) {
            return Err(ReleaseError::InvalidSignature);
        }
        if matches!(self.algorithm, SignatureAlgorithm::Fixture) && !policy.allow_fixture {
            return Err(ReleaseError::InvalidSignature);
        }
        self.trace.validate()
    }
}

/// Signing pipeline descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureDescriptor<'a> {
    /// Signing pipeline label.
    pub name: &'a str,
    /// Schema version.
    pub schema: &'static str,
    /// Signature policy.
    pub policy: SignaturePolicy,
    /// Descriptor metadata classification.
    pub data_class: DataClass,
    /// Descriptor metadata redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> SignatureDescriptor<'a> {
    /// Creates a signing descriptor.
    pub const fn new(name: &'a str, policy: SignaturePolicy) -> Self {
        Self {
            name,
            schema: SIGNING_SCHEMA_VERSION,
            policy,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates descriptor metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.name, MAX_SIGNER_LABEL_LEN)?;
        if self.schema != SIGNING_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidSignature);
        }
        self.policy.validate()?;
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Validates digest bytes under a signing/checksum policy.
pub fn validate_digest(digest: ReleaseDigest, policy: SignaturePolicy) -> ReleaseResult<()> {
    policy.validate()?;
    if policy.require_nonzero_digest && digest.iter().all(|byte| *byte == 0) {
        return Err(ReleaseError::InvalidChecksum);
    }
    Ok(())
}

/// Digest plus optional signature proof.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedDigest<'a> {
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Digest bytes.
    pub digest: ReleaseDigest,
    /// Signature proof.
    pub proof: Option<SignatureProof<'a>>,
}

impl<'a> SignedDigest<'a> {
    /// Creates an unsigned digest.
    pub const fn new(checksum_algorithm: ChecksumAlgorithm, digest: ReleaseDigest) -> Self {
        Self {
            checksum_algorithm,
            digest,
            proof: None,
        }
    }

    /// Attaches signature proof.
    pub const fn with_proof(mut self, proof: SignatureProof<'a>) -> Self {
        self.proof = Some(proof);
        self
    }

    /// Signs the digest after authorization.
    pub fn sign(
        &mut self,
        rights: ReleaseRights,
        proof: SignatureProof<'a>,
        policy: SignaturePolicy,
    ) -> ReleaseResult<()> {
        rights.require(ReleaseRights::SIGN)?;
        if proof.state.is_accepted(policy.allow_fixture) {
            rights
                .require(ReleaseRights::AUDIT)
                .map_err(|_| ReleaseError::AuditRequired)?;
        }
        validate_digest(self.digest, policy)?;
        proof.validate(policy)?;
        self.proof = Some(proof);
        Ok(())
    }

    /// Validates signed digest metadata.
    pub fn validate(self, policy: SignaturePolicy) -> ReleaseResult<()> {
        validate_digest(self.digest, policy)?;
        match self.proof {
            Some(proof) => proof.validate(policy),
            None if policy.require_signature => Err(ReleaseError::SignatureRequired),
            None => Ok(()),
        }
    }
}
