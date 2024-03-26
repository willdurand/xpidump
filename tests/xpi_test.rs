use std::io::Cursor;
use xpidump::xpi;
use zip::ZipArchive;

fn assert_signature(
    signature: xpi::Signature,
    kind: xpi::SignatureKind,
    is_staging: bool,
    algorithm: &str,
) {
    assert!(signature.exists());
    assert_eq!(kind, signature.kind());
    assert_eq!(is_staging, signature.is_staging());
    assert_eq!(algorithm, signature.algorithm.expect("expect algorithm"));
}

#[test]
fn test_prod_regular_addon() {
    let bytes = include_bytes!("fixtures/amo_info-1.25.0.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = xpi::XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert_eq!(
        "{db55bb9b-0d9f-407f-9b65-da9dd29c8d32}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "1.25.0",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        xpi.signatures.pkcs7,
        xpi::SignatureKind::Regular,
        false,
        "SHA-1",
    );
    assert_signature(
        xpi.signatures.cose,
        xpi::SignatureKind::Regular,
        false,
        "ES256",
    );
}

#[test]
fn test_prod_old_regular_addon() {
    let bytes = include_bytes!("fixtures/colorzilla-3.3.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = xpi::XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.manifest.id.is_none());
    assert_eq!("3.3", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(
        xpi.signatures.pkcs7,
        xpi::SignatureKind::Regular,
        false,
        "SHA-1",
    );
    assert!(!xpi.signatures.cose.exists());
}

#[test]
fn test_prod_privileged_addon() {
    let bytes = include_bytes!("fixtures/remote-settings-devtools.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = xpi::XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
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
        xpi::SignatureKind::Privileged,
        false,
        "SHA-256",
    );
    assert_signature(
        xpi.signatures.cose,
        xpi::SignatureKind::Privileged,
        false,
        "ES256",
    );
}

#[test]
fn test_staging_regular_addon() {
    let bytes = include_bytes!("fixtures/dev-new.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = xpi::XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert_eq!(
        "{c208c857-c691-4c69-bfa9-3c2b04f4a0ec}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!("16.0", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(
        xpi.signatures.pkcs7,
        xpi::SignatureKind::Regular,
        true,
        "SHA-1",
    );
    assert_signature(
        xpi.signatures.cose,
        xpi::SignatureKind::Regular,
        true,
        "ES256",
    );
}

#[test]
fn test_staging_old_recommended_addon() {
    let bytes = include_bytes!("fixtures/dev-old-recommended.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = xpi::XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert_eq!("alex3@mail.com", xpi.manifest.id.expect("expect add-on ID"));
    assert_eq!("1.1", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(
        xpi.signatures.pkcs7,
        xpi::SignatureKind::Regular,
        true,
        "SHA-1",
    );
    assert!(xpi.signatures.cose.exists());
}

#[test]
fn test_staging_system_addon() {
    let bytes = include_bytes!("fixtures/webcompat.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = xpi::XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert_eq!(
        "webcompat@mozilla.org",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "125.1.0buildid20240321.174451",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        xpi.signatures.pkcs7,
        xpi::SignatureKind::System,
        true,
        "SHA-256",
    );
    assert_signature(
        xpi.signatures.cose,
        xpi::SignatureKind::System,
        true,
        "ES256",
    );
}
