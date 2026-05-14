//! Release manifest, artifact, repository, evidence, and approval contracts.

use crate::{
    image::BuildProfile,
    sbom::{SbomDocument, SbomStatus},
    signing::{validate_digest, ChecksumAlgorithm, ReleaseDigest, SignaturePolicy},
    validate_redaction, validate_release_label, DataClass, RedactionState, ReleaseError,
    ReleaseResult, ReleaseRights, TraceContext,
};

/// Release manifest schema emitted by this crate version.
pub const MANIFEST_SCHEMA_VERSION: &str = "alani.release.manifest.v1";
/// Maximum release label length.
pub const MAX_RELEASE_LABEL_LEN: usize = 160;
/// Maximum release artifacts represented by this skeleton.
pub const MAX_RELEASE_ARTIFACTS: usize = 256;
/// Maximum repository records represented by this skeleton.
pub const MAX_REPOSITORY_RECORDS: usize = 64;
/// Maximum release evidence items represented by this skeleton.
pub const MAX_EVIDENCE_ITEMS: usize = 256;

const CHECKSUM_POLICY: SignaturePolicy = SignaturePolicy {
    require_signature: false,
    allow_fixture: true,
    require_nonzero_digest: true,
    max_signature_bytes: crate::signing::MAX_SIGNATURE_BYTES,
};

/// Release manifest lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseState {
    /// Manifest is being assembled.
    Draft = 0,
    /// Manifest is a release candidate.
    Candidate = 1,
    /// Required approval gates passed.
    Approved = 2,
    /// Release was published.
    Published = 3,
    /// Release was revoked.
    Revoked = 4,
}

impl ReleaseState {
    /// Returns `true` when manifest contents may be changed.
    pub const fn allows_mutation(self) -> bool {
        matches!(self, Self::Draft | Self::Candidate)
    }
}

/// Release artifact kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseArtifactKind {
    /// Built release image.
    Image = 0,
    /// SBOM document.
    Sbom = 1,
    /// Checksum list.
    ChecksumList = 2,
    /// Signature artifact.
    Signature = 3,
    /// Release notes.
    ReleaseNotes = 4,
    /// Documentation bundle.
    DocsBundle = 5,
    /// Corpus bundle.
    CorpusBundle = 6,
    /// Repository template bundle.
    TemplateBundle = 7,
    /// Repository catalog.
    RepositoryCatalog = 8,
    /// Build log or CI evidence.
    BuildLog = 9,
    /// Config profile bundle.
    ConfigBundle = 10,
}

/// Release evidence kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    /// Build log or transcript.
    BuildLog = 0,
    /// CI run evidence.
    CiRun = 1,
    /// Approval record.
    Approval = 2,
    /// Checksum evidence.
    ChecksumList = 3,
    /// SBOM evidence.
    Sbom = 4,
    /// Signature evidence.
    Signature = 5,
    /// Corpus validation evidence.
    CorpusValidation = 6,
    /// Bundle check evidence.
    BundleCheck = 7,
    /// Security review evidence.
    SecurityReview = 8,
    /// Release notes evidence.
    ReleaseNotes = 9,
}

/// Approval gate required by a release policy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalGate {
    /// Build output produced.
    Build = 0,
    /// Tests passed.
    Tests = 1,
    /// Bundle check passed.
    BundleCheck = 2,
    /// Security review completed.
    SecurityReview = 3,
    /// Release owner approved.
    ReleaseOwner = 4,
    /// Legal or data-source review completed.
    LegalDataReview = 5,
    /// Corpus validation completed.
    CorpusValidation = 6,
}

/// Release validation policy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePolicy {
    /// Require every non-signature artifact to be signed.
    pub require_signatures: bool,
    /// Require an SBOM document.
    pub require_sbom: bool,
    /// Require checksum validation for artifacts, repositories, and evidence.
    pub require_checksums: bool,
    /// Require bundle check evidence.
    pub require_bundle_check: bool,
    /// Require corpus validation evidence.
    pub require_corpus_validation: bool,
    /// Require security approval.
    pub require_security_approval: bool,
    /// Require release owner approval.
    pub require_release_owner_approval: bool,
    /// Minimum repository records expected.
    pub min_repositories: usize,
}

impl ReleasePolicy {
    /// Default release-like policy aligned with Doc 51/63.
    pub const DEFAULT: Self = Self {
        require_signatures: true,
        require_sbom: true,
        require_checksums: true,
        require_bundle_check: true,
        require_corpus_validation: true,
        require_security_approval: true,
        require_release_owner_approval: true,
        min_repositories: 32,
    };

    /// Host-mode fixture policy.
    pub const HOST_FIXTURE: Self = Self {
        require_signatures: true,
        require_sbom: true,
        require_checksums: true,
        require_bundle_check: true,
        require_corpus_validation: true,
        require_security_approval: false,
        require_release_owner_approval: true,
        min_repositories: 1,
    };

    /// Validates policy metadata against concrete capacities.
    pub const fn validate(self, repository_capacity: usize) -> ReleaseResult<()> {
        if self.min_repositories == 0 || self.min_repositories > repository_capacity {
            Err(ReleaseError::InvalidManifest)
        } else {
            Ok(())
        }
    }
}

impl Default for ReleasePolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Manifest descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestDescriptor<'a> {
    /// Manifest name.
    pub name: &'a str,
    /// Release version label.
    pub release_version: &'a str,
    /// Schema version.
    pub schema: &'static str,
    /// Build profile.
    pub build_profile: BuildProfile,
    /// Descriptor metadata classification.
    pub data_class: DataClass,
    /// Descriptor metadata redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> ManifestDescriptor<'a> {
    /// Creates a manifest descriptor.
    pub const fn new(name: &'a str, release_version: &'a str, build_profile: BuildProfile) -> Self {
        Self {
            name,
            release_version,
            schema: MANIFEST_SCHEMA_VERSION,
            build_profile,
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
        validate_release_label(self.name, MAX_RELEASE_LABEL_LEN)?;
        validate_release_label(self.release_version, MAX_RELEASE_LABEL_LEN)?;
        if self.schema != MANIFEST_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidManifest);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Release artifact record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseArtifact<'a> {
    /// Artifact name.
    pub name: &'a str,
    /// Artifact URI.
    pub uri: &'a str,
    /// Artifact kind.
    pub kind: ReleaseArtifactKind,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Artifact checksum.
    pub checksum: ReleaseDigest,
    /// Whether signature evidence exists for this artifact.
    pub signed: bool,
    /// Artifact metadata classification.
    pub data_class: DataClass,
    /// Artifact metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> ReleaseArtifact<'a> {
    /// Creates a release artifact record.
    pub const fn new(
        name: &'a str,
        uri: &'a str,
        kind: ReleaseArtifactKind,
        size_bytes: u64,
        checksum_algorithm: ChecksumAlgorithm,
        checksum: ReleaseDigest,
    ) -> Self {
        Self {
            name,
            uri,
            kind,
            size_bytes,
            checksum_algorithm,
            checksum,
            signed: false,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Marks signature evidence present or absent.
    pub const fn signed(mut self, signed: bool) -> Self {
        self.signed = signed;
        self
    }

    /// Sets classification and redaction state.
    pub const fn classified(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Validates artifact metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.name, MAX_RELEASE_LABEL_LEN)?;
        validate_release_label(self.uri, MAX_RELEASE_LABEL_LEN)?;
        if self.size_bytes == 0 {
            return Err(ReleaseError::InvalidArtifact);
        }
        validate_digest(self.checksum, CHECKSUM_POLICY)?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Repository release record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryRecord<'a> {
    /// Repository name.
    pub name: &'a str,
    /// Repository version.
    pub version: &'a str,
    /// Repository owner.
    pub owner: &'a str,
    /// Repository tier.
    pub tier: &'a str,
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Repository checksum.
    pub checksum: ReleaseDigest,
    /// Whether the repository is included in the release bundle.
    pub included: bool,
}

impl<'a> RepositoryRecord<'a> {
    /// Creates a repository record.
    pub const fn new(
        name: &'a str,
        version: &'a str,
        owner: &'a str,
        tier: &'a str,
        checksum_algorithm: ChecksumAlgorithm,
        checksum: ReleaseDigest,
    ) -> Self {
        Self {
            name,
            version,
            owner,
            tier,
            checksum_algorithm,
            checksum,
            included: true,
        }
    }

    /// Marks the repository included or excluded.
    pub const fn included(mut self, included: bool) -> Self {
        self.included = included;
        self
    }

    /// Validates repository metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.name, MAX_RELEASE_LABEL_LEN)?;
        validate_release_label(self.version, MAX_RELEASE_LABEL_LEN)?;
        validate_release_label(self.owner, MAX_RELEASE_LABEL_LEN)?;
        validate_release_label(self.tier, MAX_RELEASE_LABEL_LEN)?;
        validate_digest(self.checksum, CHECKSUM_POLICY)?;
        if !self.included {
            return Err(ReleaseError::InvalidRepository);
        }
        Ok(())
    }
}

/// Release evidence record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceItem<'a> {
    /// Evidence kind.
    pub kind: EvidenceKind,
    /// Evidence URI.
    pub uri: &'a str,
    /// Evidence owner.
    pub owner: &'a str,
    /// Approval gate satisfied by this evidence, if applicable.
    pub gate: Option<ApprovalGate>,
    /// Whether evidence was approved.
    pub approved: bool,
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Evidence checksum.
    pub checksum: ReleaseDigest,
    /// Evidence metadata classification.
    pub data_class: DataClass,
    /// Evidence metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> EvidenceItem<'a> {
    /// Creates a release evidence item.
    pub const fn new(
        kind: EvidenceKind,
        uri: &'a str,
        owner: &'a str,
        checksum_algorithm: ChecksumAlgorithm,
        checksum: ReleaseDigest,
    ) -> Self {
        Self {
            kind,
            uri,
            owner,
            gate: None,
            approved: false,
            checksum_algorithm,
            checksum,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Marks evidence as satisfying an approval gate.
    pub const fn with_gate(mut self, gate: ApprovalGate, approved: bool) -> Self {
        self.gate = Some(gate);
        self.approved = approved;
        self
    }

    /// Sets classification and redaction state.
    pub const fn classified(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Validates evidence metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.uri, MAX_RELEASE_LABEL_LEN)?;
        validate_release_label(self.owner, MAX_RELEASE_LABEL_LEN)?;
        validate_digest(self.checksum, CHECKSUM_POLICY)?;
        if matches!(self.kind, EvidenceKind::Approval) && self.gate.is_none() {
            return Err(ReleaseError::InvalidEvidence);
        }
        if self.gate.is_some() && !self.approved {
            return Err(ReleaseError::ApprovalRequired);
        }
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Fixed-capacity release manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest<'a, const A: usize, const R: usize, const E: usize> {
    /// Manifest descriptor.
    pub descriptor: ManifestDescriptor<'a>,
    /// Release state.
    pub state: ReleaseState,
    /// Release validation policy.
    pub policy: ReleasePolicy,
    /// Optional SBOM document.
    pub sbom: Option<SbomDocument<'a>>,
    artifacts: [Option<ReleaseArtifact<'a>>; A],
    artifact_len: usize,
    repositories: [Option<RepositoryRecord<'a>>; R],
    repository_len: usize,
    evidence: [Option<EvidenceItem<'a>>; E],
    evidence_len: usize,
    sealed: bool,
}

impl<'a, const A: usize, const R: usize, const E: usize> ReleaseManifest<'a, A, R, E> {
    /// Creates an empty release manifest.
    pub const fn new(descriptor: ManifestDescriptor<'a>, policy: ReleasePolicy) -> Self {
        Self {
            descriptor,
            state: ReleaseState::Draft,
            policy,
            sbom: None,
            artifacts: [None; A],
            artifact_len: 0,
            repositories: [None; R],
            repository_len: 0,
            evidence: [None; E],
            evidence_len: 0,
            sealed: false,
        }
    }

    /// Returns artifact count.
    pub const fn artifact_len(&self) -> usize {
        self.artifact_len
    }

    /// Returns repository count.
    pub const fn repository_len(&self) -> usize {
        self.repository_len
    }

    /// Returns evidence count.
    pub const fn evidence_len(&self) -> usize {
        self.evidence_len
    }

    /// Returns artifact slots.
    pub const fn artifacts(&self) -> &[Option<ReleaseArtifact<'a>>; A] {
        &self.artifacts
    }

    /// Returns repository slots.
    pub const fn repositories(&self) -> &[Option<RepositoryRecord<'a>>; R] {
        &self.repositories
    }

    /// Returns evidence slots.
    pub const fn evidence(&self) -> &[Option<EvidenceItem<'a>>; E] {
        &self.evidence
    }

    /// Returns `true` when the manifest is sealed.
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Attaches an SBOM after authorization.
    pub fn set_sbom(&mut self, rights: ReleaseRights, sbom: SbomDocument<'a>) -> ReleaseResult<()> {
        rights.require(ReleaseRights::GENERATE_SBOM)?;
        self.ensure_mutable()?;
        sbom.validate()?;
        self.sbom = Some(sbom);
        self.state = ReleaseState::Candidate;
        Ok(())
    }

    /// Adds a release artifact record.
    pub fn add_artifact(
        &mut self,
        rights: ReleaseRights,
        artifact: ReleaseArtifact<'a>,
    ) -> ReleaseResult<()> {
        rights.require(ReleaseRights::ASSEMBLE_IMAGE)?;
        self.ensure_mutable()?;
        artifact.validate()?;
        if self.artifact_len >= A || self.artifact_len >= MAX_RELEASE_ARTIFACTS {
            return Err(ReleaseError::CapacityExceeded);
        }
        let mut index = 0;
        while index < A {
            if let Some(existing) = self.artifacts[index] {
                if existing.name == artifact.name || existing.uri == artifact.uri {
                    return Err(ReleaseError::Duplicate);
                }
            }
            index += 1;
        }
        self.artifacts[self.artifact_len] = Some(artifact);
        self.artifact_len += 1;
        self.state = ReleaseState::Candidate;
        Ok(())
    }

    /// Adds a repository record.
    pub fn add_repository(
        &mut self,
        rights: ReleaseRights,
        repository: RepositoryRecord<'a>,
    ) -> ReleaseResult<()> {
        rights.require(ReleaseRights::ASSEMBLE_IMAGE)?;
        self.ensure_mutable()?;
        repository.validate()?;
        if self.repository_len >= R || self.repository_len >= MAX_REPOSITORY_RECORDS {
            return Err(ReleaseError::CapacityExceeded);
        }
        let mut index = 0;
        while index < R {
            if let Some(existing) = self.repositories[index] {
                if existing.name == repository.name {
                    return Err(ReleaseError::Duplicate);
                }
            }
            index += 1;
        }
        self.repositories[self.repository_len] = Some(repository);
        self.repository_len += 1;
        self.state = ReleaseState::Candidate;
        Ok(())
    }

    /// Adds release evidence.
    pub fn add_evidence(
        &mut self,
        rights: ReleaseRights,
        evidence: EvidenceItem<'a>,
    ) -> ReleaseResult<()> {
        rights.require(ReleaseRights::AUDIT)?;
        self.ensure_mutable()?;
        evidence.validate()?;
        if self.evidence_len >= E || self.evidence_len >= MAX_EVIDENCE_ITEMS {
            return Err(ReleaseError::CapacityExceeded);
        }
        let mut index = 0;
        while index < E {
            if let Some(existing) = self.evidence[index] {
                if existing.uri == evidence.uri {
                    return Err(ReleaseError::Duplicate);
                }
            }
            index += 1;
        }
        self.evidence[self.evidence_len] = Some(evidence);
        self.evidence_len += 1;
        self.state = ReleaseState::Candidate;
        Ok(())
    }

    /// Marks the release approved after authorization and gate validation.
    pub fn approve(&mut self, rights: ReleaseRights) -> ReleaseResult<()> {
        rights.require(ReleaseRights::APPROVE)?;
        rights
            .require(ReleaseRights::AUDIT)
            .map_err(|_| ReleaseError::AuditRequired)?;
        self.validate_for_publish()?;
        self.state = ReleaseState::Approved;
        Ok(())
    }

    /// Publishes the release after approval.
    pub fn publish(&mut self, rights: ReleaseRights) -> ReleaseResult<()> {
        rights.require(ReleaseRights::PUBLISH)?;
        rights
            .require(ReleaseRights::AUDIT)
            .map_err(|_| ReleaseError::AuditRequired)?;
        if self.state != ReleaseState::Approved {
            return Err(ReleaseError::InvalidState);
        }
        self.validate_for_publish()?;
        self.state = ReleaseState::Published;
        self.sealed = true;
        Ok(())
    }

    /// Validates manifest invariants.
    pub fn validate(&self) -> ReleaseResult<()> {
        self.descriptor.validate()?;
        self.policy.validate(R)?;
        if self.artifact_len > A
            || self.repository_len > R
            || self.evidence_len > E
            || self.artifact_len > MAX_RELEASE_ARTIFACTS
            || self.repository_len > MAX_REPOSITORY_RECORDS
            || self.evidence_len > MAX_EVIDENCE_ITEMS
        {
            return Err(ReleaseError::InvalidManifest);
        }
        self.validate_artifacts()?;
        self.validate_repositories()?;
        self.validate_evidence()?;
        if let Some(sbom) = self.sbom {
            sbom.validate()?;
        }
        Ok(())
    }

    /// Validates manifest for approval or publication.
    pub fn validate_for_publish(&self) -> ReleaseResult<()> {
        self.validate()?;
        if self.policy.require_sbom {
            match self.sbom {
                Some(sbom)
                    if matches!(sbom.status, SbomStatus::Complete | SbomStatus::Verified) =>
                {
                    sbom.validate()?
                }
                _ => return Err(ReleaseError::SbomRequired),
            }
        }
        if self.repository_len < self.policy.min_repositories {
            return Err(ReleaseError::InvalidManifest);
        }
        if self.policy.require_signatures && !self.all_artifacts_signed() {
            return Err(ReleaseError::SignatureRequired);
        }
        if self.policy.require_bundle_check && !self.has_gate(ApprovalGate::BundleCheck) {
            return Err(ReleaseError::ApprovalRequired);
        }
        if self.policy.require_corpus_validation && !self.has_gate(ApprovalGate::CorpusValidation) {
            return Err(ReleaseError::ApprovalRequired);
        }
        if self.policy.require_security_approval && !self.has_gate(ApprovalGate::SecurityReview) {
            return Err(ReleaseError::ApprovalRequired);
        }
        if self.policy.require_release_owner_approval && !self.has_gate(ApprovalGate::ReleaseOwner)
        {
            return Err(ReleaseError::ApprovalRequired);
        }
        if !self.has_kind(ReleaseArtifactKind::RepositoryCatalog)
            || !self.has_kind(ReleaseArtifactKind::DocsBundle)
            || !self.has_kind(ReleaseArtifactKind::CorpusBundle)
            || !self.has_kind(ReleaseArtifactKind::TemplateBundle)
            || !self.has_kind(ReleaseArtifactKind::ChecksumList)
        {
            return Err(ReleaseError::InvalidManifest);
        }
        Ok(())
    }

    fn ensure_mutable(&self) -> ReleaseResult<()> {
        if self.sealed {
            return Err(ReleaseError::Sealed);
        }
        if !self.state.allows_mutation() {
            return Err(ReleaseError::InvalidState);
        }
        Ok(())
    }

    fn validate_artifacts(&self) -> ReleaseResult<()> {
        let mut count = 0;
        let mut index = 0;
        while index < A {
            if let Some(artifact) = self.artifacts[index] {
                artifact.validate()?;
                count += 1;
                let mut other = index + 1;
                while other < A {
                    if let Some(other_artifact) = self.artifacts[other] {
                        if artifact.name == other_artifact.name
                            || artifact.uri == other_artifact.uri
                        {
                            return Err(ReleaseError::Duplicate);
                        }
                    }
                    other += 1;
                }
            }
            index += 1;
        }
        if count != self.artifact_len {
            return Err(ReleaseError::InvalidManifest);
        }
        Ok(())
    }

    fn validate_repositories(&self) -> ReleaseResult<()> {
        let mut count = 0;
        let mut index = 0;
        while index < R {
            if let Some(repository) = self.repositories[index] {
                repository.validate()?;
                count += 1;
                let mut other = index + 1;
                while other < R {
                    if let Some(other_repository) = self.repositories[other] {
                        if repository.name == other_repository.name {
                            return Err(ReleaseError::Duplicate);
                        }
                    }
                    other += 1;
                }
            }
            index += 1;
        }
        if count != self.repository_len {
            return Err(ReleaseError::InvalidManifest);
        }
        Ok(())
    }

    fn validate_evidence(&self) -> ReleaseResult<()> {
        let mut count = 0;
        let mut index = 0;
        while index < E {
            if let Some(evidence) = self.evidence[index] {
                evidence.validate()?;
                count += 1;
                let mut other = index + 1;
                while other < E {
                    if let Some(other_evidence) = self.evidence[other] {
                        if evidence.uri == other_evidence.uri {
                            return Err(ReleaseError::Duplicate);
                        }
                    }
                    other += 1;
                }
            }
            index += 1;
        }
        if count != self.evidence_len {
            return Err(ReleaseError::InvalidManifest);
        }
        Ok(())
    }

    fn has_kind(&self, kind: ReleaseArtifactKind) -> bool {
        let mut index = 0;
        while index < A {
            if let Some(artifact) = self.artifacts[index] {
                if artifact.kind == kind {
                    return true;
                }
            }
            index += 1;
        }
        false
    }

    fn has_gate(&self, gate: ApprovalGate) -> bool {
        let mut index = 0;
        while index < E {
            if let Some(evidence) = self.evidence[index] {
                if evidence.gate == Some(gate) && evidence.approved {
                    return true;
                }
            }
            index += 1;
        }
        false
    }

    fn all_artifacts_signed(&self) -> bool {
        let mut index = 0;
        while index < A {
            if let Some(artifact) = self.artifacts[index] {
                if !matches!(artifact.kind, ReleaseArtifactKind::Signature) && !artifact.signed {
                    return false;
                }
            }
            index += 1;
        }
        true
    }
}
