use alani_release::{
    signing::SignedDigest, ApprovalGate, BuildProfile, ChecksumAlgorithm, ComponentKind,
    ComponentLicense, Compression, EvidenceItem, EvidenceKind, ImageArtifact, ImageBuildPlan,
    ImageDescriptor, ImageFormat, ImageInput, ImageInputKind, ImageLayout, ManifestDescriptor,
    ReleaseArtifact, ReleaseArtifactKind, ReleaseDigest, ReleaseError, ReleaseManifest,
    ReleasePolicy, ReleaseRights, RepositoryRecord, SbomComponent, SbomDescriptor, SbomDocument,
    SbomFormat, SbomStatus, SignatureAlgorithm, SignaturePolicy, SignatureProof, SignatureState,
    SigningKey, TraceContext, VerificationStatus, DIGEST_LEN,
};

fn digest(byte: u8) -> ReleaseDigest {
    [byte; DIGEST_LEN]
}

fn artifact(name: &'static str, kind: ReleaseArtifactKind, byte: u8) -> ReleaseArtifact<'static> {
    ReleaseArtifact::new(
        name,
        name,
        kind,
        1024,
        ChecksumAlgorithm::Sha256,
        digest(byte),
    )
    .signed(true)
}

fn evidence(uri: &'static str, gate: ApprovalGate, byte: u8) -> EvidenceItem<'static> {
    EvidenceItem::new(
        EvidenceKind::Approval,
        uri,
        "release-team",
        ChecksumAlgorithm::Sha256,
        digest(byte),
    )
    .with_gate(gate, true)
}

#[test]
fn repository_identity_and_catalog_are_stable() {
    assert_eq!(alani_release::repository_name(), "alani-release");
    assert_eq!(
        alani_release::module_names(),
        &["image", "sbom", "signing", "manifest"]
    );
    assert_eq!(alani_release::ALIAS_IMAGE, "alani-image");
    assert!(alani_release::release_catalog().validate().is_ok());
}

#[test]
fn signing_policy_rejects_zero_digest_fixture_without_policy_and_missing_audit() {
    let key = SigningKey::new("fixture-key", SignatureAlgorithm::Fixture, "release-team");
    let proof = SignatureProof::new(key, b"fixture-signature", SignatureState::FixtureSigned)
        .with_signed_counter(1)
        .with_verification(VerificationStatus::Verified);

    assert_eq!(
        proof.validate(SignaturePolicy::DEFAULT),
        Err(ReleaseError::SignatureRequired)
    );
    assert!(proof.validate(SignaturePolicy::HOST_FIXTURE).is_ok());

    assert_eq!(
        alani_release::validate_digest([0; DIGEST_LEN], SignaturePolicy::HOST_FIXTURE),
        Err(ReleaseError::InvalidChecksum)
    );

    let mut signed_digest = SignedDigest::new(ChecksumAlgorithm::Sha256, digest(1));
    assert_eq!(
        signed_digest.sign(ReleaseRights::SIGN, proof, SignaturePolicy::HOST_FIXTURE),
        Err(ReleaseError::AuditRequired)
    );
    assert!(signed_digest
        .sign(
            ReleaseRights::SIGN.union(ReleaseRights::AUDIT),
            proof,
            SignaturePolicy::HOST_FIXTURE,
        )
        .is_ok());
}

#[test]
fn sbom_documents_enforce_license_and_generation_gates() {
    let components = [SbomComponent::new(
        "alani-release",
        "0.1.0",
        "release-team",
        ComponentKind::RustCrate,
        "crates/alani-release",
        ChecksumAlgorithm::Sha256,
        digest(2),
    )];
    let sbom = SbomDocument::new(
        SbomDescriptor::new("release-sbom", SbomFormat::Alani),
        &components,
    )
    .generated_by("alani-release", 1)
    .license_review_complete(true);

    assert!(sbom
        .generate(ReleaseRights::GENERATE_SBOM.union(ReleaseRights::AUDIT))
        .is_ok());

    let prohibited = [components[0].with_license(ComponentLicense::Prohibited)];
    let bad_sbom = SbomDocument::new(
        SbomDescriptor::new("bad-sbom", SbomFormat::Alani),
        &prohibited,
    )
    .generated_by("alani-release", 1)
    .license_review_complete(true);
    assert_eq!(bad_sbom.validate(), Err(ReleaseError::LicenseDenied));

    let restricted = [components[0].with_license(ComponentLicense::Restricted)];
    let review_needed = SbomDocument::new(
        SbomDescriptor::new("review-sbom", SbomFormat::Alani),
        &restricted,
    )
    .with_status(SbomStatus::Complete)
    .generated_by("alani-release", 1);
    assert_eq!(
        review_needed.validate(),
        Err(ReleaseError::ApprovalRequired)
    );
}

#[test]
fn image_plan_requires_doc51_release_inputs_and_seals_after_build() {
    let descriptor = ImageDescriptor::new(
        "alani-release",
        ImageFormat::ZipBundle,
        ImageLayout::SpecBundle,
        BuildProfile::ReleaseCandidate,
    );
    let mut plan = ImageBuildPlan::<8>::new(descriptor);
    let rights = ReleaseRights::ASSEMBLE_IMAGE.union(ReleaseRights::AUDIT);

    plan.add_input(
        rights,
        ImageInput::new(
            "docs/spec.md",
            ImageInputKind::Docs,
            10,
            ChecksumAlgorithm::Sha256,
            digest(3),
        ),
    )
    .unwrap();
    assert_eq!(plan.validate(), Err(ReleaseError::InvalidImage));

    for (path, kind, byte) in [
        ("corpus/data.jsonl", ImageInputKind::Corpus, 4),
        (
            "templates/alani-release",
            ImageInputKind::RepositoryTemplate,
            5,
        ),
        ("templates/workspace", ImageInputKind::WorkspaceTemplate, 6),
        ("tools/check_bundle.py", ImageInputKind::ToolingScript, 7),
        ("docs/repositories", ImageInputKind::RepositorySpec, 8),
        ("release/evidence.json", ImageInputKind::ReleaseEvidence, 9),
    ] {
        plan.add_input(
            rights,
            ImageInput::new(path, kind, 10, ChecksumAlgorithm::Sha256, digest(byte)),
        )
        .unwrap();
    }

    let artifact = ImageArtifact::new(
        "release/alani.zip",
        ImageFormat::ZipBundle,
        ImageLayout::SpecBundle,
        4096,
        ChecksumAlgorithm::Sha256,
        digest(10),
    )
    .with_compression(Compression::Deflate);
    let artifact = plan.build(rights, artifact).unwrap();
    assert!(artifact.sealed);

    plan.seal(ReleaseRights::ADMIN).unwrap();
    assert_eq!(
        plan.add_input(
            rights,
            ImageInput::new(
                "extra",
                ImageInputKind::ReleaseEvidence,
                1,
                ChecksumAlgorithm::Sha256,
                digest(11),
            ),
        ),
        Err(ReleaseError::Sealed)
    );
}

#[test]
fn release_manifest_requires_sbom_signatures_repositories_and_approval_gates() {
    let components = [SbomComponent::new(
        "alani-release",
        "0.1.0",
        "release-team",
        ComponentKind::RustCrate,
        "crates/alani-release",
        ChecksumAlgorithm::Sha256,
        digest(12),
    )];
    let sbom = SbomDocument::new(
        SbomDescriptor::new("release-sbom", SbomFormat::Alani),
        &components,
    )
    .with_status(SbomStatus::Complete)
    .generated_by("alani-release", 1)
    .license_review_complete(true);

    let mut manifest = ReleaseManifest::<8, 2, 8>::new(
        ManifestDescriptor::new("alani", "0.2.0-draft", BuildProfile::ReleaseCandidate),
        ReleasePolicy::HOST_FIXTURE,
    );
    let assemble = ReleaseRights::ASSEMBLE_IMAGE;

    manifest
        .set_sbom(ReleaseRights::GENERATE_SBOM, sbom)
        .unwrap();
    manifest
        .add_repository(
            assemble,
            RepositoryRecord::new(
                "alani-release",
                "0.1.0",
                "release-team",
                "MVK-required",
                ChecksumAlgorithm::Sha256,
                digest(13),
            ),
        )
        .unwrap();

    for (name, kind, byte) in [
        ("release/image.zip", ReleaseArtifactKind::Image, 14),
        ("release/sbom.json", ReleaseArtifactKind::Sbom, 15),
        (
            "release/checksums.txt",
            ReleaseArtifactKind::ChecksumList,
            16,
        ),
        ("release/docs.zip", ReleaseArtifactKind::DocsBundle, 17),
        ("release/corpus.zip", ReleaseArtifactKind::CorpusBundle, 18),
        (
            "release/templates.zip",
            ReleaseArtifactKind::TemplateBundle,
            19,
        ),
        (
            "release/repos.json",
            ReleaseArtifactKind::RepositoryCatalog,
            20,
        ),
    ] {
        manifest
            .add_artifact(assemble, artifact(name, kind, byte))
            .unwrap();
    }

    assert_eq!(
        manifest.approve(ReleaseRights::APPROVE.union(ReleaseRights::AUDIT)),
        Err(ReleaseError::ApprovalRequired)
    );

    for item in [
        evidence("evidence/bundle", ApprovalGate::BundleCheck, 21),
        evidence("evidence/corpus", ApprovalGate::CorpusValidation, 22),
        evidence("evidence/owner", ApprovalGate::ReleaseOwner, 23),
    ] {
        manifest.add_evidence(ReleaseRights::AUDIT, item).unwrap();
    }

    manifest
        .approve(ReleaseRights::APPROVE.union(ReleaseRights::AUDIT))
        .unwrap();
    manifest
        .publish(ReleaseRights::PUBLISH.union(ReleaseRights::AUDIT))
        .unwrap();
    assert!(manifest.is_sealed());

    let mut unsigned_manifest = ReleaseManifest::<8, 2, 8>::new(
        ManifestDescriptor::new("alani", "0.2.0-draft", BuildProfile::ReleaseCandidate),
        ReleasePolicy::HOST_FIXTURE,
    );
    unsigned_manifest
        .set_sbom(ReleaseRights::GENERATE_SBOM, sbom)
        .unwrap();
    unsigned_manifest
        .add_repository(
            assemble,
            RepositoryRecord::new(
                "alani-release",
                "0.1.0",
                "release-team",
                "MVK-required",
                ChecksumAlgorithm::Sha256,
                digest(24),
            ),
        )
        .unwrap();
    unsigned_manifest
        .add_artifact(
            assemble,
            ReleaseArtifact::new(
                "release/repos.json",
                "release/repos.json",
                ReleaseArtifactKind::RepositoryCatalog,
                1,
                ChecksumAlgorithm::Sha256,
                digest(25),
            ),
        )
        .unwrap();
    assert_eq!(
        unsigned_manifest.validate_for_publish(),
        Err(ReleaseError::SignatureRequired)
    );
}

#[test]
fn invalid_trace_and_reserved_rights_fail_closed() {
    assert_eq!(
        TraceContext::EMPTY.with_flags(1 << 31).validate(),
        Err(ReleaseError::ReservedBits)
    );
    assert_eq!(
        ReleaseRights::from_bits(1 << 63),
        Err(ReleaseError::ReservedBits)
    );
}
