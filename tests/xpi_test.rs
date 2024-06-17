use std::io::Cursor;
use std::time::Duration;
use xpidump::{Date, Environment, RecommendationState, Signature, SignatureKind, XPI};
use zip::ZipArchive;

fn assert_signature(signature: &Signature, kind: SignatureKind, env: Environment, algorithm: &str) {
    assert!(signature.exists());
    assert_eq!(kind, signature.kind());
    assert_eq!(env, signature.env());
    assert_eq!(
        algorithm,
        signature.algorithm.as_ref().expect("expect algorithm")
    );

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
    assert!(!xpi.is_enterprise());
    assert_eq!(
        "{db55bb9b-0d9f-407f-9b65-da9dd29c8d32}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "1.25.0",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Regular,
        Environment::Production,
        "SHA-1",
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(1743724800)),
        xpi.signatures.pkcs7.certificates[0].end_date
    );

    assert_signature(
        &xpi.signatures.cose,
        SignatureKind::Regular,
        Environment::Production,
        "ES256",
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(1743724800)),
        xpi.signatures.cose.certificates[0].end_date
    );
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
    assert!(!xpi.is_enterprise());
    assert_eq!("3.3", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Regular,
        Environment::Production,
        "SHA-1",
    );
    // Verify TeletexString values.
    assert_eq!(
        "{6AC85730-7D0F-4de0-B3FA-21142DD85326}",
        xpi.signatures.pkcs7.certificates[1].common_name
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(1741996362)),
        xpi.signatures.pkcs7.certificates[0].end_date
    );
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
    assert!(!xpi.is_enterprise());
    assert_eq!(
        "remote-settings-devtools@mozilla.com",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "1.8.1buildid20230725.150941",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Privileged,
        Environment::Production,
        "SHA-256",
    );
    assert_signature(
        &xpi.signatures.cose,
        SignatureKind::Privileged,
        Environment::Production,
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
    assert!(!xpi.is_enterprise());
    assert_eq!(
        "{c208c857-c691-4c69-bfa9-3c2b04f4a0ec}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!("16.0", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Regular,
        Environment::Staging,
        "SHA-1",
    );
    assert_signature(
        &xpi.signatures.cose,
        SignatureKind::Regular,
        Environment::Staging,
        "ES256",
    );
}

#[test]
fn test_staging_old_recommended_addon() {
    let bytes = include_bytes!("fixtures/dev-old-recommended.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.is_recommended());
    assert!(!xpi.is_enterprise());
    assert_eq!(
        vec![
            RecommendationState::Recommended,
            RecommendationState::RecommendedAndroid
        ],
        xpi.recommendation.unwrap().states
    );
    assert_eq!("alex3@mail.com", xpi.manifest.id.expect("expect add-on ID"));
    assert_eq!("1.1", xpi.manifest.version.expect("expect add-on version"));

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Regular,
        Environment::Staging,
        "SHA-1",
    );
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
    assert!(!xpi.is_enterprise());
    assert_eq!(
        "webcompat@mozilla.org",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "125.1.0buildid20240321.174451",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::System,
        Environment::Staging,
        "SHA-256",
    );
    assert_signature(
        &xpi.signatures.cose,
        SignatureKind::System,
        Environment::Staging,
        "ES256",
    );
}

#[test]
fn test_long_id() {
    let bytes = include_bytes!("fixtures/laboratory_by_mozilla-3.0.8.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.is_recommended());
    assert!(!xpi.is_enterprise());
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
    assert!(!xpi.is_enterprise());
    assert!(!xpi.signatures.has_signatures());
}

#[test]
fn test_staging_line_extension() {
    let bytes = include_bytes!("fixtures/line-staging-cas-cur.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.is_recommended());
    assert!(!xpi.is_enterprise());
    assert_eq!(
        "{0cdc308b-4c2a-497d-916a-164d602ed358}",
        xpi.manifest.id.expect("expect add-on ID")
    );
    assert_eq!(
        "109.2",
        xpi.manifest.version.expect("expect add-on version")
    );

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Regular,
        Environment::Staging,
        "SHA-1",
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(1741910400)),
        xpi.signatures.pkcs7.certificates[0].end_date
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(2026818980)),
        xpi.signatures.pkcs7.certificates[1].end_date
    );

    assert_signature(
        &xpi.signatures.cose,
        SignatureKind::Regular,
        Environment::Staging,
        "ES256",
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(1741910400)),
        xpi.signatures.cose.certificates[0].end_date
    );
    assert_eq!(
        Date::utc_time_from_duration(Duration::from_secs(2026818980)),
        xpi.signatures.cose.certificates[1].end_date
    );
}

#[test]
fn test_amo_localdev() {
    let bytes = include_bytes!("fixtures/amo-localdev.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(!xpi.is_recommended());
    assert!(!xpi.is_enterprise());
    assert_eq!(
        "a-test-extension@will.drnd.me",
        xpi.manifest.id.expect("expect add-on ID")
    );

    assert_signature(
        &xpi.signatures.pkcs7,
        SignatureKind::Regular,
        Environment::Development,
        "SHA-1",
    );
    assert_signature(
        &xpi.signatures.cose,
        SignatureKind::Regular,
        Environment::Development,
        "ES256",
    );
}

#[test]
fn test_enterprise() {
    let bytes = include_bytes!("fixtures/enterprise-dev.xpi");
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader).unwrap();

    let xpi = XPI::new(&mut archive);

    assert!(xpi.manifest.exists());
    assert!(xpi.is_enterprise());
}
