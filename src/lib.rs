#![cfg_attr(not(feature = "std"), no_std)]

//! Reproducible image, release manifest, SBOM, checksum, signing, and evidence contracts.
//!
//! `alani-release` owns release assembly metadata while package, SDK, docs,
//! corpus, and config repositories stabilize their public outputs. The API is
//! dependency-free, `no_std` compatible, and explicit about provenance,
//! checksums, signing, redaction, approval gates, and audit evidence.

pub mod image;
pub mod manifest;
pub mod sbom;
pub mod signing;

pub use image::{
    BuildProfile, Compression, ImageArtifact, ImageBuildPlan, ImageDescriptor, ImageFormat,
    ImageInput, ImageInputKind, ImageLayout, ImagePhase, ImageState, ImageStep,
    IMAGE_SCHEMA_VERSION, MAX_IMAGE_INPUTS, MAX_IMAGE_LABEL_LEN, MAX_IMAGE_URI_LEN,
};
pub use manifest::{
    ApprovalGate, EvidenceItem, EvidenceKind, ManifestDescriptor, ReleaseArtifact,
    ReleaseArtifactKind, ReleaseManifest, ReleasePolicy, ReleaseState, RepositoryRecord,
    MANIFEST_SCHEMA_VERSION, MAX_EVIDENCE_ITEMS, MAX_RELEASE_ARTIFACTS, MAX_RELEASE_LABEL_LEN,
    MAX_REPOSITORY_RECORDS,
};
pub use sbom::{
    ComponentKind, ComponentLicense, SbomComponent, SbomDescriptor, SbomDocument, SbomFormat,
    SbomRelationship, SbomRelationshipKind, SbomStatus, MAX_SBOM_COMPONENTS, MAX_SBOM_LABEL_LEN,
    MAX_SBOM_RELATIONSHIPS, SBOM_SCHEMA_VERSION,
};
pub use signing::{
    validate_digest, ChecksumAlgorithm, ReleaseDigest, SignatureAlgorithm, SignatureDescriptor,
    SignaturePolicy, SignatureProof, SignatureState, SignedDigest, SigningKey, VerificationStatus,
    DIGEST_LEN, MAX_KEY_ID_LEN, MAX_SIGNATURE_BYTES, SIGNING_SCHEMA_VERSION,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-release";
/// Compatibility alias recorded by the repository spec.
pub const ALIAS_IMAGE: &str = "alani-image";
/// Crate version.
pub const VERSION: &str = "0.1.0";
/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["image", "sbom", "signing", "manifest"];

/// Feature bit for release manifests and repository records.
pub const RELEASE_FEATURE_MANIFESTS: u64 = 1 << 0;
/// Feature bit for reproducible image plans.
pub const RELEASE_FEATURE_IMAGES: u64 = 1 << 1;
/// Feature bit for SBOM documents.
pub const RELEASE_FEATURE_SBOM: u64 = 1 << 2;
/// Feature bit for checksum records.
pub const RELEASE_FEATURE_CHECKSUMS: u64 = 1 << 3;
/// Feature bit for signing and verification metadata.
pub const RELEASE_FEATURE_SIGNING: u64 = 1 << 4;
/// Feature bit for release evidence and approval gates.
pub const RELEASE_FEATURE_EVIDENCE: u64 = 1 << 5;
/// Feature bit for trace-context propagation.
pub const RELEASE_FEATURE_TRACE_CONTEXT: u64 = 1 << 6;
/// Feature bit for host-mode bundle verification.
pub const RELEASE_FEATURE_HOST_VERIFICATION: u64 = 1 << 7;

/// All release feature bits known by this crate version.
pub const RELEASE_KNOWN_FEATURES: u64 = RELEASE_FEATURE_MANIFESTS
    | RELEASE_FEATURE_IMAGES
    | RELEASE_FEATURE_SBOM
    | RELEASE_FEATURE_CHECKSUMS
    | RELEASE_FEATURE_SIGNING
    | RELEASE_FEATURE_EVIDENCE
    | RELEASE_FEATURE_TRACE_CONTEXT
    | RELEASE_FEATURE_HOST_VERIFICATION;

/// Caller may read release metadata.
pub const RELEASE_RIGHT_READ: u64 = 1 << 0;
/// Caller may assemble release images.
pub const RELEASE_RIGHT_ASSEMBLE_IMAGE: u64 = 1 << 1;
/// Caller may generate SBOMs.
pub const RELEASE_RIGHT_GENERATE_SBOM: u64 = 1 << 2;
/// Caller may sign artifacts.
pub const RELEASE_RIGHT_SIGN: u64 = 1 << 3;
/// Caller may verify checksums and signatures.
pub const RELEASE_RIGHT_VERIFY: u64 = 1 << 4;
/// Caller may publish release metadata.
pub const RELEASE_RIGHT_PUBLISH: u64 = 1 << 5;
/// Caller may approve release gates.
pub const RELEASE_RIGHT_APPROVE: u64 = 1 << 6;
/// Caller may emit or preserve audit evidence.
pub const RELEASE_RIGHT_AUDIT: u64 = 1 << 7;
/// Caller has administrative release authority.
pub const RELEASE_RIGHT_ADMIN: u64 = 1 << 8;

/// All release rights known by this crate version.
pub const RELEASE_KNOWN_RIGHTS: u64 = RELEASE_RIGHT_READ
    | RELEASE_RIGHT_ASSEMBLE_IMAGE
    | RELEASE_RIGHT_GENERATE_SBOM
    | RELEASE_RIGHT_SIGN
    | RELEASE_RIGHT_VERIFY
    | RELEASE_RIGHT_PUBLISH
    | RELEASE_RIGHT_APPROVE
    | RELEASE_RIGHT_AUDIT
    | RELEASE_RIGHT_ADMIN;

/// Trace flag indicating the event was sampled.
pub const TRACE_FLAG_SAMPLED: u32 = 1 << 0;
/// Trace flag indicating debug metadata may be attached by a trusted sink.
pub const TRACE_FLAG_DEBUG: u32 = 1 << 1;
/// Trace flag indicating a release boundary was crossed.
pub const TRACE_FLAG_RELEASE_BOUNDARY: u32 = 1 << 2;
/// Trace flag indicating audit evidence must be preserved.
pub const TRACE_FLAG_AUDIT_REQUIRED: u32 = 1 << 3;

/// Trace flags known by this crate version.
pub const TRACE_KNOWN_FLAGS: u32 =
    TRACE_FLAG_SAMPLED | TRACE_FLAG_DEBUG | TRACE_FLAG_RELEASE_BOUNDARY | TRACE_FLAG_AUDIT_REQUIRED;

/// Result alias for release validation and host-mode operations.
pub type ReleaseResult<T> = Result<T, ReleaseError>;

/// Error taxonomy for images, manifests, SBOMs, signatures, and release evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    /// A required field was empty or omitted.
    MissingField,
    /// A bounded field exceeded its documented maximum length.
    FieldTooLong,
    /// A label contained a disallowed character.
    InvalidLabel,
    /// Unknown feature, capability, flag, or rights bits were supplied.
    ReservedBits,
    /// Release manifest metadata failed validation.
    InvalidManifest,
    /// Image plan or image artifact metadata failed validation.
    InvalidImage,
    /// SBOM metadata failed validation.
    InvalidSbom,
    /// Signature metadata failed validation.
    InvalidSignature,
    /// Digest or checksum metadata failed validation.
    InvalidChecksum,
    /// Release artifact metadata failed validation.
    InvalidArtifact,
    /// Release evidence metadata failed validation.
    InvalidEvidence,
    /// Repository record metadata failed validation.
    InvalidRepository,
    /// License state does not allow release publication.
    LicenseDenied,
    /// Caller lacks required release authority.
    AccessDenied,
    /// Operation attempted to mutate a sealed target.
    Sealed,
    /// Fixed-capacity collection is full.
    CapacityExceeded,
    /// Duplicate entry was supplied.
    Duplicate,
    /// State machine transition is not allowed.
    InvalidState,
    /// Required approval gate is missing.
    ApprovalRequired,
    /// Required signing material is missing.
    SignatureRequired,
    /// Required SBOM is missing.
    SbomRequired,
    /// Required checksum is missing or mismatched.
    ChecksumRequired,
    /// Trace context was malformed.
    InvalidTrace,
    /// Redaction state is incompatible with data classification.
    InvalidRedaction,
    /// Audit evidence is required but not authorized or present.
    AuditRequired,
    /// Internal invariant failed.
    Internal,
}

impl ReleaseError {
    /// Stable reason label for diagnostics and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingField => "missing_field",
            Self::FieldTooLong => "field_too_long",
            Self::InvalidLabel => "invalid_label",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidManifest => "invalid_manifest",
            Self::InvalidImage => "invalid_image",
            Self::InvalidSbom => "invalid_sbom",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidChecksum => "invalid_checksum",
            Self::InvalidArtifact => "invalid_artifact",
            Self::InvalidEvidence => "invalid_evidence",
            Self::InvalidRepository => "invalid_repository",
            Self::LicenseDenied => "license_denied",
            Self::AccessDenied => "access_denied",
            Self::Sealed => "sealed",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::Duplicate => "duplicate",
            Self::InvalidState => "invalid_state",
            Self::ApprovalRequired => "approval_required",
            Self::SignatureRequired => "signature_required",
            Self::SbomRequired => "sbom_required",
            Self::ChecksumRequired => "checksum_required",
            Self::InvalidTrace => "invalid_trace",
            Self::InvalidRedaction => "invalid_redaction",
            Self::AuditRequired => "audit_required",
            Self::Internal => "internal",
        }
    }

    /// Returns `true` when this error represents a fail-closed release boundary.
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ReservedBits
                | Self::InvalidChecksum
                | Self::InvalidSignature
                | Self::LicenseDenied
                | Self::AccessDenied
                | Self::Sealed
                | Self::ApprovalRequired
                | Self::SignatureRequired
                | Self::SbomRequired
                | Self::ChecksumRequired
                | Self::InvalidRedaction
                | Self::AuditRequired
        )
    }
}

/// Data sensitivity classification for release metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DataClass {
    /// Public metadata.
    Public = 0,
    /// Operational metadata suitable for trusted operators.
    Operational = 1,
    /// Sensitive metadata requiring redaction before broad export.
    Sensitive = 2,
    /// Secret metadata or signing material that must not be exported raw.
    Secret = 3,
}

impl DataClass {
    /// Returns `true` when data with this class must be redacted before export.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }
}

/// Redaction state applied to release metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionState {
    /// Public fields only.
    Public = 0,
    /// Operational metadata only.
    Operational = 1,
    /// Sensitive fields were redacted.
    SensitiveRedacted = 2,
    /// Secret fields were redacted.
    SecretRedacted = 3,
    /// Sensitive fields are present and must not be exported broadly.
    UnredactedSensitive = 4,
}

/// Stable trace context copied from observability/syscall layers when present.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Trace identifier shared across component boundaries.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
}

impl TraceContext {
    /// Empty trace context used when no trace is available.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
    };

    /// Creates a root trace context.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: TRACE_FLAG_SAMPLED,
        }
    }

    /// Creates a child trace context preserving trace flags.
    pub const fn child(self, span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: self.span_id,
            flags: self.flags,
        }
    }

    /// Sets trace flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Returns `true` when both trace and span identifiers are present.
    pub const fn is_present(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Validates trace metadata.
    pub const fn validate(self) -> ReleaseResult<()> {
        if self.flags & !TRACE_KNOWN_FLAGS != 0 {
            return Err(ReleaseError::ReservedBits);
        }
        if self.trace_id == 0 && self.span_id == 0 && self.parent_span_id == 0 {
            return Ok(());
        }
        if self.trace_id == 0 || self.span_id == 0 {
            return Err(ReleaseError::InvalidTrace);
        }
        if self.parent_span_id != 0 && self.parent_span_id == self.span_id {
            return Err(ReleaseError::InvalidTrace);
        }
        Ok(())
    }
}

/// Release authority bitmap.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReleaseRights(pub u64);

impl ReleaseRights {
    /// No authority.
    pub const NONE: Self = Self(0);
    /// Read release metadata.
    pub const READ: Self = Self(RELEASE_RIGHT_READ);
    /// Assemble release images.
    pub const ASSEMBLE_IMAGE: Self = Self(RELEASE_RIGHT_ASSEMBLE_IMAGE);
    /// Generate SBOMs.
    pub const GENERATE_SBOM: Self = Self(RELEASE_RIGHT_GENERATE_SBOM);
    /// Sign artifacts.
    pub const SIGN: Self = Self(RELEASE_RIGHT_SIGN);
    /// Verify checksums and signatures.
    pub const VERIFY: Self = Self(RELEASE_RIGHT_VERIFY);
    /// Publish releases.
    pub const PUBLISH: Self = Self(RELEASE_RIGHT_PUBLISH);
    /// Approve release gates.
    pub const APPROVE: Self = Self(RELEASE_RIGHT_APPROVE);
    /// Preserve audit evidence.
    pub const AUDIT: Self = Self(RELEASE_RIGHT_AUDIT);
    /// Administrative release authority.
    pub const ADMIN: Self = Self(RELEASE_RIGHT_ADMIN);
    /// Full authority for host-mode administrative tests.
    pub const ADMINISTRATOR: Self = Self(RELEASE_KNOWN_RIGHTS);

    /// Creates rights from raw bits after rejecting unknown bits.
    pub const fn from_bits(bits: u64) -> ReleaseResult<Self> {
        if bits & !RELEASE_KNOWN_RIGHTS != 0 {
            Err(ReleaseError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw rights bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all required rights are present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Combines two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates reserved bits.
    pub const fn validate(self) -> ReleaseResult<()> {
        if self.0 & !RELEASE_KNOWN_RIGHTS != 0 {
            Err(ReleaseError::ReservedBits)
        } else {
            Ok(())
        }
    }

    /// Fails closed when required rights are absent.
    pub const fn require(self, required: Self) -> ReleaseResult<()> {
        if self.0 & !RELEASE_KNOWN_RIGHTS != 0 || required.0 & !RELEASE_KNOWN_RIGHTS != 0 {
            return Err(ReleaseError::ReservedBits);
        }
        if self.contains(required) {
            Ok(())
        } else {
            Err(ReleaseError::AccessDenied)
        }
    }
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Compact root view of the release crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Compatibility alias.
    pub alias: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Feature bitmap.
    pub features: u64,
    /// Rights bitmap recognized by this crate version.
    pub rights: u64,
    /// Image schema version.
    pub image_schema: &'static str,
    /// SBOM schema version.
    pub sbom_schema: &'static str,
    /// Signing schema version.
    pub signing_schema: &'static str,
    /// Manifest schema version.
    pub manifest_schema: &'static str,
}

impl ReleaseCatalog {
    /// Current release catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        alias: ALIAS_IMAGE,
        version: VERSION,
        features: RELEASE_KNOWN_FEATURES,
        rights: RELEASE_KNOWN_RIGHTS,
        image_schema: IMAGE_SCHEMA_VERSION,
        sbom_schema: SBOM_SCHEMA_VERSION,
        signing_schema: SIGNING_SCHEMA_VERSION,
        manifest_schema: MANIFEST_SCHEMA_VERSION,
    };

    /// Validates catalog metadata.
    pub const fn validate(self) -> ReleaseResult<()> {
        if self.repository.is_empty()
            || self.alias.is_empty()
            || self.version.is_empty()
            || self.image_schema.is_empty()
            || self.sbom_schema.is_empty()
            || self.signing_schema.is_empty()
            || self.manifest_schema.is_empty()
        {
            return Err(ReleaseError::MissingField);
        }
        if self.features & !RELEASE_KNOWN_FEATURES != 0 || self.rights & !RELEASE_KNOWN_RIGHTS != 0
        {
            return Err(ReleaseError::ReservedBits);
        }
        Ok(())
    }
}

/// Current release catalog.
pub const RELEASE_CATALOG: ReleaseCatalog = ReleaseCatalog::CURRENT;

/// Returns the current release catalog.
pub const fn release_catalog() -> ReleaseCatalog {
    ReleaseCatalog::CURRENT
}

/// Validates redaction state for a data class.
pub const fn validate_redaction(
    data_class: DataClass,
    redaction: RedactionState,
) -> ReleaseResult<()> {
    match data_class {
        DataClass::Public => {
            if matches!(redaction, RedactionState::Public) {
                Ok(())
            } else {
                Err(ReleaseError::InvalidRedaction)
            }
        }
        DataClass::Operational => {
            if matches!(redaction, RedactionState::Operational) {
                Ok(())
            } else {
                Err(ReleaseError::InvalidRedaction)
            }
        }
        DataClass::Sensitive => {
            if matches!(
                redaction,
                RedactionState::SensitiveRedacted | RedactionState::SecretRedacted
            ) {
                Ok(())
            } else {
                Err(ReleaseError::InvalidRedaction)
            }
        }
        DataClass::Secret => {
            if matches!(redaction, RedactionState::SecretRedacted) {
                Ok(())
            } else {
                Err(ReleaseError::InvalidRedaction)
            }
        }
    }
}

/// Validates a stable release label or URI-like field.
pub fn validate_release_label(label: &str, max_len: usize) -> ReleaseResult<()> {
    if label.is_empty() {
        return Err(ReleaseError::MissingField);
    }
    if label.len() > max_len {
        return Err(ReleaseError::FieldTooLong);
    }
    if !label.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/' | b'@' | b'+' | b'#')
    }) {
        return Err(ReleaseError::InvalidLabel);
    }
    Ok(())
}
