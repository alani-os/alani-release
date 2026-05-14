//! Reproducible image build plan and artifact contracts.

use crate::{
    signing::{validate_digest, ChecksumAlgorithm, ReleaseDigest, SignaturePolicy},
    validate_redaction, validate_release_label, DataClass, RedactionState, ReleaseError,
    ReleaseResult, ReleaseRights, TraceContext,
};

/// Image metadata schema emitted by this crate version.
pub const IMAGE_SCHEMA_VERSION: &str = "alani.release.image.v1";
/// Maximum image input records represented by this skeleton.
pub const MAX_IMAGE_INPUTS: usize = 256;
/// Maximum image label length.
pub const MAX_IMAGE_LABEL_LEN: usize = 128;
/// Maximum artifact URI length.
pub const MAX_IMAGE_URI_LEN: usize = 256;

const CHECKSUM_POLICY: SignaturePolicy = SignaturePolicy {
    require_signature: false,
    allow_fixture: true,
    require_nonzero_digest: true,
    max_signature_bytes: crate::signing::MAX_SIGNATURE_BYTES,
};

/// Release build profile.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildProfile {
    /// Developer-local build.
    Dev = 0,
    /// CI build.
    Ci = 1,
    /// Release candidate build.
    ReleaseCandidate = 2,
    /// Published release build.
    Release = 3,
}

impl BuildProfile {
    /// Returns `true` when the build profile requires complete release evidence.
    pub const fn requires_release_evidence(self) -> bool {
        matches!(self, Self::ReleaseCandidate | Self::Release)
    }
}

/// Release image format.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageFormat {
    /// Reproducible ZIP bundle.
    ZipBundle = 0,
    /// TAR-like host bundle.
    TarBundle = 1,
    /// Raw bootable disk image.
    RawDiskImage = 2,
    /// QCOW2 bootable disk image.
    Qcow2 = 3,
    /// Directory tree used by host tests.
    DirectoryTree = 4,
}

/// Release image layout.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageLayout {
    /// Complete specification bundle.
    SpecBundle = 0,
    /// Bootable operating system image.
    BootableImage = 1,
    /// Repository catalog and templates.
    RepositoryCatalog = 2,
    /// Corpus data and schema bundle.
    CorpusBundle = 3,
    /// Workspace template bundle.
    WorkspaceTemplate = 4,
}

/// Image compression.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    /// No compression.
    None = 0,
    /// Deflate compression.
    Deflate = 1,
    /// Host-mode zstd fixture.
    ZstdFixture = 2,
}

/// Image build lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageState {
    /// Build plan is being assembled.
    Draft = 0,
    /// Build plan is complete.
    Planned = 1,
    /// Image has been built.
    Built = 2,
    /// Image has been verified.
    Verified = 3,
    /// Image has been published.
    Published = 4,
    /// Image build failed.
    Failed = 5,
}

impl ImageState {
    /// Returns `true` when inputs may still be added.
    pub const fn allows_planning(self) -> bool {
        matches!(self, Self::Draft | Self::Planned)
    }
}

/// Image build phase.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ImagePhase {
    /// Collect inputs.
    CollectInputs = 0,
    /// Validate expanded bundle.
    ValidateBundle = 1,
    /// Build image.
    BuildImage = 2,
    /// Generate checksums.
    GenerateChecksums = 3,
    /// Generate SBOM.
    GenerateSbom = 4,
    /// Sign artifacts.
    SignArtifacts = 5,
    /// Verify evidence.
    VerifyEvidence = 6,
    /// Publish release.
    Publish = 7,
}

/// Image input kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageInputKind {
    /// Built binary.
    Binary = 0,
    /// Documentation source or rendered docs.
    Docs = 1,
    /// Corpus data, schema, taxonomy, or datasheet.
    Corpus = 2,
    /// Individual repository template.
    RepositoryTemplate = 3,
    /// Workspace template.
    WorkspaceTemplate = 4,
    /// Tooling script.
    ToolingScript = 5,
    /// Release evidence file.
    ReleaseEvidence = 6,
    /// Package artifact.
    Package = 7,
    /// Repository specification or catalog.
    RepositorySpec = 8,
}

/// Image descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageDescriptor<'a> {
    /// Image name.
    pub name: &'a str,
    /// Schema version.
    pub schema: &'static str,
    /// Image format.
    pub format: ImageFormat,
    /// Image layout.
    pub layout: ImageLayout,
    /// Build profile.
    pub build_profile: BuildProfile,
    /// Descriptor metadata classification.
    pub data_class: DataClass,
    /// Descriptor metadata redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> ImageDescriptor<'a> {
    /// Creates an image descriptor.
    pub const fn new(
        name: &'a str,
        format: ImageFormat,
        layout: ImageLayout,
        build_profile: BuildProfile,
    ) -> Self {
        Self {
            name,
            schema: IMAGE_SCHEMA_VERSION,
            format,
            layout,
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
        validate_release_label(self.name, MAX_IMAGE_LABEL_LEN)?;
        if self.schema != IMAGE_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidImage);
        }
        if matches!(self.build_profile, BuildProfile::Release)
            && matches!(self.format, ImageFormat::DirectoryTree)
        {
            return Err(ReleaseError::InvalidImage);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Image input record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageInput<'a> {
    /// Input path or URI.
    pub path: &'a str,
    /// Input kind.
    pub kind: ImageInputKind,
    /// Whether this input is required for release completeness.
    pub required: bool,
    /// Input size in bytes.
    pub size_bytes: u64,
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Input checksum.
    pub checksum: ReleaseDigest,
    /// Input metadata classification.
    pub data_class: DataClass,
    /// Input metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> ImageInput<'a> {
    /// Creates an image input record.
    pub const fn new(
        path: &'a str,
        kind: ImageInputKind,
        size_bytes: u64,
        checksum_algorithm: ChecksumAlgorithm,
        checksum: ReleaseDigest,
    ) -> Self {
        Self {
            path,
            kind,
            required: true,
            size_bytes,
            checksum_algorithm,
            checksum,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Marks the input required or optional.
    pub const fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Sets classification and redaction state.
    pub const fn classified(mut self, data_class: DataClass, redaction: RedactionState) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Validates image input metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.path, MAX_IMAGE_URI_LEN)?;
        if self.size_bytes == 0 {
            return Err(ReleaseError::InvalidImage);
        }
        validate_digest(self.checksum, CHECKSUM_POLICY)?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Built image artifact metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageArtifact<'a> {
    /// Artifact URI.
    pub uri: &'a str,
    /// Image format.
    pub format: ImageFormat,
    /// Image layout.
    pub layout: ImageLayout,
    /// Compression.
    pub compression: Compression,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Checksum algorithm.
    pub checksum_algorithm: ChecksumAlgorithm,
    /// Artifact checksum.
    pub checksum: ReleaseDigest,
    /// Whether the artifact is sealed against mutation.
    pub sealed: bool,
    /// Artifact metadata classification.
    pub data_class: DataClass,
    /// Artifact metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> ImageArtifact<'a> {
    /// Creates image artifact metadata.
    pub const fn new(
        uri: &'a str,
        format: ImageFormat,
        layout: ImageLayout,
        size_bytes: u64,
        checksum_algorithm: ChecksumAlgorithm,
        checksum: ReleaseDigest,
    ) -> Self {
        Self {
            uri,
            format,
            layout,
            compression: Compression::None,
            size_bytes,
            checksum_algorithm,
            checksum,
            sealed: false,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Sets compression.
    pub const fn with_compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Marks the artifact sealed or mutable.
    pub const fn sealed(mut self, sealed: bool) -> Self {
        self.sealed = sealed;
        self
    }

    /// Validates image artifact metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.uri, MAX_IMAGE_URI_LEN)?;
        if self.size_bytes == 0 {
            return Err(ReleaseError::InvalidArtifact);
        }
        validate_digest(self.checksum, CHECKSUM_POLICY)?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Build step record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageStep<'a> {
    /// Build phase.
    pub phase: ImagePhase,
    /// Step label.
    pub label: &'a str,
    /// Number of inputs observed by the step.
    pub input_count: usize,
    /// Number of outputs produced by the step.
    pub output_count: usize,
    /// Whether durable audit evidence is required.
    pub requires_audit: bool,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> ImageStep<'a> {
    /// Creates a build step.
    pub const fn new(phase: ImagePhase, label: &'a str) -> Self {
        Self {
            phase,
            label,
            input_count: 0,
            output_count: 0,
            requires_audit: matches!(
                phase,
                ImagePhase::ValidateBundle
                    | ImagePhase::GenerateChecksums
                    | ImagePhase::GenerateSbom
                    | ImagePhase::SignArtifacts
                    | ImagePhase::VerifyEvidence
                    | ImagePhase::Publish
            ),
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets observed counts.
    pub const fn with_counts(mut self, input_count: usize, output_count: usize) -> Self {
        self.input_count = input_count;
        self.output_count = output_count;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates build step metadata.
    pub fn validate(self) -> ReleaseResult<()> {
        validate_release_label(self.label, MAX_IMAGE_LABEL_LEN)?;
        if matches!(
            self.phase,
            ImagePhase::BuildImage
                | ImagePhase::GenerateChecksums
                | ImagePhase::GenerateSbom
                | ImagePhase::SignArtifacts
                | ImagePhase::VerifyEvidence
                | ImagePhase::Publish
        ) && self.output_count == 0
        {
            return Err(ReleaseError::InvalidImage);
        }
        self.trace.validate()
    }
}

/// Fixed-capacity release image build plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageBuildPlan<'a, const N: usize> {
    /// Image descriptor.
    pub descriptor: ImageDescriptor<'a>,
    /// Image state.
    pub state: ImageState,
    inputs: [Option<ImageInput<'a>>; N],
    len: usize,
    sealed: bool,
}

impl<'a, const N: usize> ImageBuildPlan<'a, N> {
    /// Creates an empty image build plan.
    pub const fn new(descriptor: ImageDescriptor<'a>) -> Self {
        Self {
            descriptor,
            state: ImageState::Draft,
            inputs: [None; N],
            len: 0,
            sealed: false,
        }
    }

    /// Returns input capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns input count.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no inputs are present.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns input slots.
    pub const fn inputs(&self) -> &[Option<ImageInput<'a>>; N] {
        &self.inputs
    }

    /// Returns `true` when the plan is sealed.
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Adds an input after authorization and duplicate checks.
    pub fn add_input(&mut self, rights: ReleaseRights, input: ImageInput<'a>) -> ReleaseResult<()> {
        rights.require(ReleaseRights::ASSEMBLE_IMAGE)?;
        if self.sealed {
            return Err(ReleaseError::Sealed);
        }
        if !self.state.allows_planning() {
            return Err(ReleaseError::InvalidState);
        }
        self.descriptor.validate()?;
        input.validate()?;
        if self.len >= N || self.len >= MAX_IMAGE_INPUTS {
            return Err(ReleaseError::CapacityExceeded);
        }
        let mut index = 0;
        while index < N {
            if let Some(existing) = self.inputs[index] {
                if existing.path == input.path {
                    return Err(ReleaseError::Duplicate);
                }
            }
            index += 1;
        }
        self.inputs[self.len] = Some(input);
        self.len += 1;
        self.state = ImageState::Planned;
        Ok(())
    }

    /// Marks the image built after validating required inputs.
    pub fn build(
        &mut self,
        rights: ReleaseRights,
        artifact: ImageArtifact<'a>,
    ) -> ReleaseResult<ImageArtifact<'a>> {
        rights.require(ReleaseRights::ASSEMBLE_IMAGE)?;
        rights
            .require(ReleaseRights::AUDIT)
            .map_err(|_| ReleaseError::AuditRequired)?;
        if self.sealed {
            return Err(ReleaseError::Sealed);
        }
        self.validate()?;
        self.validate_release_completeness()?;
        artifact.validate()?;
        if artifact.format != self.descriptor.format || artifact.layout != self.descriptor.layout {
            return Err(ReleaseError::InvalidImage);
        }
        self.state = ImageState::Built;
        Ok(artifact.sealed(true))
    }

    /// Marks the image verified.
    pub fn verify(&mut self, rights: ReleaseRights) -> ReleaseResult<()> {
        rights.require(ReleaseRights::VERIFY)?;
        if self.state != ImageState::Built {
            return Err(ReleaseError::InvalidState);
        }
        self.state = ImageState::Verified;
        Ok(())
    }

    /// Seals the plan against mutation.
    pub fn seal(&mut self, rights: ReleaseRights) -> ReleaseResult<()> {
        rights.require(ReleaseRights::ADMIN)?;
        self.validate()?;
        self.sealed = true;
        Ok(())
    }

    /// Validates plan invariants.
    pub fn validate(&self) -> ReleaseResult<()> {
        self.descriptor.validate()?;
        if self.len == 0 || self.len > N || self.len > MAX_IMAGE_INPUTS {
            return Err(ReleaseError::InvalidImage);
        }
        let mut count = 0;
        let mut index = 0;
        while index < N {
            if let Some(input) = self.inputs[index] {
                input.validate()?;
                count += 1;
            }
            index += 1;
        }
        if count != self.len {
            return Err(ReleaseError::InvalidImage);
        }
        if self.descriptor.build_profile.requires_release_evidence() {
            self.validate_release_completeness()?;
        }
        Ok(())
    }

    fn has_kind(&self, kind: ImageInputKind) -> bool {
        let mut index = 0;
        while index < N {
            if let Some(input) = self.inputs[index] {
                if input.kind == kind && input.required {
                    return true;
                }
            }
            index += 1;
        }
        false
    }

    fn validate_release_completeness(&self) -> ReleaseResult<()> {
        if self.descriptor.build_profile.requires_release_evidence()
            && !(self.has_kind(ImageInputKind::Docs)
                && self.has_kind(ImageInputKind::Corpus)
                && self.has_kind(ImageInputKind::RepositoryTemplate)
                && self.has_kind(ImageInputKind::WorkspaceTemplate)
                && self.has_kind(ImageInputKind::ToolingScript)
                && self.has_kind(ImageInputKind::RepositorySpec)
                && self.has_kind(ImageInputKind::ReleaseEvidence))
        {
            return Err(ReleaseError::InvalidImage);
        }
        Ok(())
    }
}
