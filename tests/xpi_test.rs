use std::io::Cursor;
use xpidump::{RecommendationState, Signature, SignatureKind, XPI};
use zip::ZipArchive;

fn assert_signature(signature: Signature, kind: SignatureKind, is_staging: bool, algorithm: &str) {
    assert!(signature.exists());
    assert_eq!(kind, signature.kind());
    assert_eq!(is_staging, signature.is_staging());
    assert_eq!(algorithm, signature.algorithm.expect("expect algorithm"));

    let expected_ou = match kind {
        SignatureKind::Privileged => "Mozilla Extensions",
        SignatureKind::Regular => "Production",
        SignatureKind::System => "Mozilla Components",
    };
    // The end certificate should contain a deterministic OU.
    assert_eq!(expected_ou, signature.certificates[1].organizational_unit);
}

#[test]
fn test_prod_regular_addon() {
    let bytes = include_bytes!("fixtures/amo_info-1.25.0.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(!xpi.is_recommended());
    assert_eq!(
        "{db55bb9b-0d9f-407f-9b65-da9dd29c8d32}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "1.25.0",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(xpi.signatures.pkcs7, SignatureKind::Regular, false, "SHA-1");
    assert_signature(xpi.signatures.cose, SignatureKind::Regular, false, "ES256");
}

#[test]
fn test_prod_old_regular_addon() {
    let bytes = include_bytes!("fixtures/colorzilla-3.3.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.manifest.id.is_none());
    assert!(!xpi.is_recommended());
    assert_eq!("3.3", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(xpi.signatures.pkcs7, SignatureKind::Regular, false, "SHA-1");
    assert!(!xpi.signatures.cose.exists());
}

#[test]
fn test_prod_privileged_addon() {
    let bytes = include_bytes!("fixtures/remote-settings-devtools.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(!xpi.is_recommended());
    assert_eq!(
        "remote-settings-devtools@mozilla.com",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "1.8.1buildid20230725.150941",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        xpi.signatures.pkcs7,
        SignatureKind::Privileged,
        false,
        "SHA-256",
    );
    assert_signature(
        xpi.signatures.cose,
        SignatureKind::Privileged,
        false,
        "ES256",
    );
}

#[test]
fn test_staging_regular_addon() {
    let bytes = include_bytes!("fixtures/dev-new.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(!xpi.is_recommended());
    assert_eq!(
        "{c208c857-c691-4c69-bfa9-3c2b04f4a0ec}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!("16.0", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(xpi.signatures.pkcs7, SignatureKind::Regular, true, "SHA-1");
    assert_signature(xpi.signatures.cose, SignatureKind::Regular, true, "ES256");
}

#[test]
fn test_staging_old_recommended_addon() {
    let bytes = include_bytes!("fixtures/dev-old-recommended.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.is_recommended());
    assert_eq!(
        vec![
            RecommendationState::Recommended,
            RecommendationState::RecommendedAndroid
        ],
        xpi.recommendation.unwrap().states
    );
    assert_eq!("alex3@mail.com", xpi.manifest.id.expect("expect add-on ID"));
    assert_eq!("1.1", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(xpi.signatures.pkcs7, SignatureKind::Regular, true, "SHA-1");
    assert!(xpi.signatures.cose.exists());
}

#[test]
fn test_staging_system_addon() {
    let bytes = include_bytes!("fixtures/webcompat.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(!xpi.is_recommended());
    assert_eq!(
        "webcompat@mozilla.org",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "125.1.0buildid20240321.174451",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(xpi.signatures.pkcs7, SignatureKind::System, true, "SHA-256");
    assert_signature(xpi.signatures.cose, SignatureKind::System, true, "ES256");
}

#[test]
fn test_long_id() {
    let bytes = include_bytes!("fixtures/laboratory_by_mozilla-3.0.8.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.is_recommended());
    assert_eq!(
        vec![RecommendationState::Line],
        xpi.recommendation.unwrap().states
    );
    assert_eq!(
        "1b2383b324c8520974ee097e46301d5ca4e076de387c02886f1c6b1503671586@pokeinthe.io",
        xpi.manifest.id.expect("expect add-on ID")
    );
    // AMO will pass the SHA-256 hash of an add-on ID to Autograph when its length is > 64 chars.
    assert_eq!(
        "237aafe39e41ad97721ba6b7d41ca597d0b9d67c54da10c079c3bb7ffc1853b3",
        xpi.signatures.pkcs7.certificates[1].common_name
    );
    assert_eq!(
        "237aafe39e41ad97721ba6b7d41ca597d0b9d67c54da10c079c3bb7ffc1853b3",
        xpi.signatures.cose.certificates[1].common_name
    );
}

#[test]
fn test_unsigned_addon() {
    let bytes = include_bytes!("fixtures/unsigned.zip");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.manifest.id.is_none());
    assert_eq!(
        "1.0",
        xpi.manifest
            .version
            .as_ref()
            .expect("expect add-on version")
    );
    assert!(!xpi.is_recommended());
    assert!(!xpi.signatures.has_signatures());
}
