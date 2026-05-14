//! Software bill of materials component and relationship contracts.

use crate::{
    signing::{validate_digest, ChecksumAlgorithm, ReleaseDigest, SignaturePolicy},
    validate_redaction, validate_release_label, DataClass, RedactionState, ReleaseError,
    ReleaseResult, ReleaseRights, TraceContext,
};

/// SBOM schema emitted by this crate version.
pub const SBOM_SCHEMA_VERSION: &str = "alani.release.sbom.v1";
/// Maximum SBOM component records represented by this skeleton.
pub const MAX_SBOM_COMPONENTS: usize = 256;
/// Maximum SBOM relationship records represented by this skeleton.
pub const MAX_SBOM_RELATIONSHIPS: usize = 512;
/// Maximum SBOM label length.
pub const MAX_SBOM_LABEL_LEN: usize = 160;

const CHECKSUM_POLICY: SignaturePolicy = SignaturePolicy {
    require_signature: false,
    allow_fixture: true,
    require_nonzero_digest: true,
    max_signature_bytes: crate::signing::MAX_SIGNATURE_BYTES,
};

/// SBOM document format.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SbomFormat {
    /// Alani compact SBOM.
    Alani = 0,
    /// SPDX-like host-mode record.
    SpdxLite = 1,
    /// CycloneDX-like host-mode record.
    CycloneDxLite = 2,
}

/// SBOM lifecycle status.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SbomStatus {
    /// Document is being assembled.
    Draft = 0,
    /// Document has all required fields.
    Complete = 1,
    /// Document has been verified by release tooling.
    Verified = 2,
}

/// SBOM component kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentKind {
    /// Source repository.
    SourceRepository = 0,
    /// Rust crate.
    RustCrate = 1,
    /// Documentation artifact.
    Documentation = 2,
    /// Corpus data artifact.
    Corpus = 3,
    /// Repository template.
    Template = 4,
    /// Tooling script.
    Tooling = 5,
    /// Built binary.
    Binary = 6,
    /// Release image.
    Image = 7,
    /// Installable package artifact.
    Package = 8,
}

/// License review state for an SBOM component.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentLicense {
    /// License approved for release.
    Approved = 0,
    /// Internal-only draft material.
    Internal = 1,
    /// License needs review before publication.
    NeedsReview = 2,
    /// Restricted material requiring an approval gate.
    Restricted = 3,
    /// Prohibited material.
    Prohibited = 4,
}

impl ComponentLicense {
    /// Returns `true` when the license may appear in a public release without override.
    pub const fn is_public_release_ready(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// SBOM relationship kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SbomRelationshipKind {
    /// Document or image contains a component.
    Contains = 0,
    /// Component depends on another component.
    DependsOn = 1,
    /// Component was generated from another component.
    GeneratedFrom = 2,
    /// Component describes another artifact.
    Describes = 3,
}

/// SBOM descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SbomDescriptor<'a> {
    /// SBOM document name.
    pub name: &'a str,
    /// Schema version.
    pub schema: &'static str,
    /// SBOM format.
    pub format: SbomFormat,
    /// Descriptor metadata classification.
    pub data_class: DataClass,
    /// Descriptor metadata redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> SbomDescriptor<'a> {
    /// Creates an SBOM descriptor.
    pub const fn new(name: &'a str, format: SbomFormat) -> Self {
        Self {
            name,
            schema: SBOM_SCHEMA_VERSION,
            format,
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
        validate_release_label(self.name, MAX_SBOM_LABEL_LEN)?;
        if self.schema != SBOM_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidSbom);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// SBOM component record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SbomComponent<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version.
    pub version: &'a str,
    /// Supplier or owner label.
    pub supplier: &'a str,
    /// Component kind.
    pub kind: ComponentKind,
    /// License review state.
    pub license: ComponentLicense,
    /// Component path or URI.
    pub path: &'a str,
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Component checksum.
    pub checksum: ReleaseDigest,
    /// Component metadata classification.
    pub data_class: DataClass,
    /// Component metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> SbomComponent<'a> {
    /// Creates an SBOM component.
    pub const fn new(
        name: &'a str,
        version: &'a str,
        supplier: &'a str,
        kind: ComponentKind,
        path: &'a str,
        checksum_algorithm: ChecksumAlgorithm,
        checksum: ReleaseDigest,
    ) -> Self {
        Self {
            name,
            version,
            supplier,
            kind,
            license: ComponentLicense::Approved,
            path,
            checksum_algorithm,
            checksum,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Sets license state.
    pub const fn with_license(mut self, license: ComponentLicense) -> Self {
        self.license = license;
        self
    }

    /// Sets classification and redaction state.
    pub const fn classified(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Validates component metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.name, MAX_SBOM_LABEL_LEN)?;
        validate_release_label(self.version, MAX_SBOM_LABEL_LEN)?;
        validate_release_label(self.supplier, MAX_SBOM_LABEL_LEN)?;
        validate_release_label(self.path, MAX_SBOM_LABEL_LEN)?;
        validate_digest(self.checksum, CHECKSUM_POLICY)?;
        if matches!(self.license, ComponentLicense::Prohibited) {
            return Err(ReleaseError::LicenseDenied);
        }
        validate_redaction(self.data_class, self.redaction)
    }
}

/// SBOM relationship record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SbomRelationship<'a> {
    /// Source component name.
    pub from: &'a str,
    /// Target component name.
    pub to: &'a str,
    /// Relationship kind.
    pub kind: SbomRelationshipKind,
}

impl<'a> SbomRelationship<'a> {
    /// Creates an SBOM relationship.
    pub const fn new(from: &'a str, to: &'a str, kind: SbomRelationshipKind) -> Self {
        Self { from, to, kind }
    }

    /// Validates relationship metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.from, MAX_SBOM_LABEL_LEN)?;
        validate_release_label(self.to, MAX_SBOM_LABEL_LEN)?;
        if self.from == self.to {
            return Err(ReleaseError::InvalidSbom);
        }
        Ok(())
    }
}

/// Complete SBOM document.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SbomDocument<'a> {
    /// SBOM descriptor.
    pub descriptor: SbomDescriptor<'a>,
    /// SBOM lifecycle status.
    pub status: SbomStatus,
    /// Component records.
    pub components: &'a [SbomComponent<'a>],
    /// Relationship records.
    pub relationships: &'a [SbomRelationship<'a>],
    /// Tool that generated the SBOM.
    pub generated_by: &'a str,
    /// Generation counter supplied by release tooling.
    pub generated_counter: u64,
    /// Whether license review has been completed.
    pub license_review_complete: bool,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> SbomDocument<'a> {
    /// Creates an SBOM document.
    pub const fn new(descriptor: SbomDescriptor<'a>, components: &'a [SbomComponent<'a>]) -> Self {
        Self {
            descriptor,
            status: SbomStatus::Draft,
            components,
            relationships: &[],
            generated_by: "",
            generated_counter: 0,
            license_review_complete: false,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets document status.
    pub const fn with_status(mut self, status: SbomStatus) -> Self {
        self.status = status;
        self
    }

    /// Sets relationships.
    pub const fn with_relationships(mut self, relationships: &'a [SbomRelationship<'a>]) -> Self {
        self.relationships = relationships;
        self
    }

    /// Sets generator metadata.
    pub const fn generated_by(mut self, generated_by: &'a str, generated_counter: u64) -> Self {
        self.generated_by = generated_by;
        self.generated_counter = generated_counter;
        self
    }

    /// Marks license review complete or incomplete.
    pub const fn license_review_complete(mut self, complete: bool) -> Self {
        self.license_review_complete = complete;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Generates the SBOM after authorization.
    pub fn generate(mut self, rights: ReleaseRights) -> ReleaseResult<Self> {
        rights.require(ReleaseRights::GENERATE_SBOM)?;
        rights
            .require(ReleaseRights::AUDIT)
            .map_err(|_| ReleaseError::AuditRequired)?;
        self.status = SbomStatus::Complete;
        self.validate()?;
        Ok(self)
    }

    /// Returns `true` when a component license requires an external release gate.
    pub fn requires_license_gate(self) -> bool {
        let mut index = 0;
        while index < self.components.len() {
            if matches!(
                self.components[index].license,
                ComponentLicense::NeedsReview | ComponentLicense::Restricted
            ) {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Validates SBOM document metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        self.descriptor.validate()?;
        if self.components.is_empty() {
            return Err(ReleaseError::MissingField);
        }
        if self.components.len() > MAX_SBOM_COMPONENTS
            || self.relationships.len() > MAX_SBOM_RELATIONSHIPS
        {
            return Err(ReleaseError::CapacityExceeded);
        }
        if matches!(self.status, SbomStatus::Complete | SbomStatus::Verified) {
            validate_release_label(self.generated_by, MAX_SBOM_LABEL_LEN)?;
            if self.generated_counter == 0 {
                return Err(ReleaseError::InvalidSbom);
            }
        }
        let mut index = 0;
        while index < self.components.len() {
            let component = self.components[index];
            component.validate()?;
            let mut other = index + 1;
            while other < self.components.len() {
                if component.name == self.components[other].name {
                    return Err(ReleaseError::Duplicate);
                }
                other += 1;
            }
            if matches!(
                component.license,
                ComponentLicense::NeedsReview | ComponentLicense::Restricted
            ) && !self.license_review_complete
            {
                return Err(ReleaseError::ApprovalRequired);
            }
            index += 1;
        }
        let mut rel_index = 0;
        while rel_index < self.relationships.len() {
            self.relationships[rel_index].validate()?;
            rel_index += 1;
        }
        if matches!(self.status, SbomStatus::Verified) && !self.license_review_complete {
            return Err(ReleaseError::ApprovalRequired);
        }
        self.trace.validate()
    }
}
