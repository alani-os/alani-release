#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_release::repository_name(), "alani-release");
    assert!(!alani_release::module_names().is_empty());
}
