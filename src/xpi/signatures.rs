use cms::cert::{
    x509::{
        attr::AttributeTypeAndValue,
        der::{
            asn1::{PrintableStringRef, Utf8StringRef},
            Decode, Encode, Tag, Tagged,
        },
    },
    CertificateChoices,
    CertificateChoices::Certificate,
};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::{
    rfc4519::{COMMON_NAME, ORGANIZATIONAL_UNIT_NAME},
    rfc5912::{ID_SHA_1, ID_SHA_256},
};
use coset::{CborSerializable, CoseSign, TaggedCborSerializable};
use std::{fmt, io, io::Read};
use zip::ZipArchive;

#[derive(Default)]
struct CertificateInfo {
    common_name: String,
    organizational_unit: String,
}

impl CertificateInfo {
    pub fn from_choices(choices: &CertificateChoices) -> Option<CertificateInfo> {
        match choices {
            Certificate(cert) => {
                let subject = &cert.tbs_certificate.subject;

                let mut common_name = "N/A".to_string();
                let mut organizational_unit = "N/A".to_string();
                for (_, rdn) in subject.0.iter().rev().enumerate() {
                    if let Some(atv) = rdn.0.get(0) {
                        match atv.oid {
                            COMMON_NAME => {
                                common_name = atv_to_string(&atv);
                            }
                            ORGANIZATIONAL_UNIT_NAME => {
                                organizational_unit = atv_to_string(&atv);
                            }
                            _ => {}
                        };
                    }
                }

                Some(CertificateInfo {
                    common_name: common_name,
                    organizational_unit: organizational_unit,
                    ..CertificateInfo::default()
                })
            }
            _ => None,
        }
    }

    fn is_staging(&self) -> bool {
        self.common_name.contains("staging")
    }
}

impl fmt::Display for CertificateInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Common Name         (CN): {}\n            Organizational Unit (OU): {}",
            self.common_name, self.organizational_unit
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum SignatureKind {
    Regular,
    Privileged,
    System,
}

impl fmt::Display for SignatureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SignatureKind::Regular => "REGULAR ADD-ON",
                SignatureKind::Privileged => "PRIVILEGED ADD-ON",
                SignatureKind::System => "SYSTEM ADD-ON",
            }
        )
    }
}

#[derive(Default)]
pub struct Signature {
    pub name: String,
    present: bool,
    pub algorithm: Option<String>,
    certificates: Vec<CertificateInfo>,
}

impl Signature {
    pub fn exists(&self) -> bool {
        self.present
    }

    pub fn is_staging(&self) -> bool {
        self.certificates.iter().any(|cert| cert.is_staging())
    }

    pub fn kind(&self) -> SignatureKind {
        if self
            .certificates
            .iter()
            .any(|cert| cert.organizational_unit == "Mozilla Extensions")
        {
            SignatureKind::Privileged
        } else if self
            .certificates
            .iter()
            .any(|cert| cert.organizational_unit == "Mozilla Components")
        {
            SignatureKind::System
        } else {
            SignatureKind::Regular
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\n   └── {} / {} / {} / {}\n   └── Certificates:",
            self.name,
            if self.present { "PRESENT" } else { "ABSENT" },
            if self.is_staging() {
                "STAGING"
            } else {
                "PRODUCTION"
            },
            self.algorithm.as_deref().unwrap_or("N/A"),
            self.kind(),
        )?;
        for cert in &self.certificates {
            write!(f, "\n        └── {}", cert)?;
        }
        Ok(())
    }
}

pub struct Signatures {
    pub pkcs7: Signature,
    pub cose: Signature,
}

impl Signatures {
    pub fn parse<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Signatures {
        Signatures {
            pkcs7: self::Signatures::parse_pkcs7(archive),
            cose: self::Signatures::parse_cose(archive),
        }
    }

    fn parse_pkcs7<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Signature {
        let has_pkcs7_manifest = match archive.by_name("META-INF/manifest.mf") {
            Ok(_) => true,
            Err(_) => false,
        };
        let has_pkcs7_mozilla = match archive.by_name("META-INF/mozilla.sf") {
            Ok(_) => true,
            Err(_) => false,
        };
        let maybe_sig_file = archive.by_name("META-INF/mozilla.rsa");
        let has_pkcs7 = has_pkcs7_manifest && has_pkcs7_mozilla && maybe_sig_file.is_ok();

        let mut algorithm = None;
        let mut certificates = vec![];
        if let Ok(mut sig_file) = maybe_sig_file {
            let mut buffer = Vec::new();
            if let Ok(_) = sig_file.read_to_end(&mut buffer) {
                let maybe_data = ContentInfo::from_der(&buffer)
                    .and_then(|ci| ci.content.to_der())
                    .and_then(|der| SignedData::from_der(&der));

                if let Ok(data) = maybe_data {
                    if let Some(choices) =
                        data.certificates.and_then(|certs| Some(certs.0.into_vec()))
                    {
                        certificates = choices
                            .iter()
                            .map(|choice| CertificateInfo::from_choices(&choice))
                            .flatten()
                            .collect();
                    }

                    let digest_algorithm = match data.signer_infos.0.get(0).unwrap().digest_alg.oid
                    {
                        ID_SHA_1 => "SHA-1",
                        ID_SHA_256 => "SHA-256",
                        _ => "unknown",
                    };
                    algorithm = Some(digest_algorithm.to_string());
                }
            }
        }

        Signature {
            name: "PKCS#7".to_string(),
            present: has_pkcs7,
            algorithm: algorithm,
            certificates: certificates,
            ..Signature::default()
        }
    }

    fn parse_cose<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Signature {
        // COSE
        let has_cose_manifest = match archive.by_name("META-INF/cose.manifest") {
            Ok(_) => true,
            Err(_) => false,
        };
        let maybe_sig_file = archive.by_name("META-INF/cose.sig");
        let has_cose = has_cose_manifest && maybe_sig_file.is_ok();

        if let Ok(mut sig_file) = maybe_sig_file {
            let mut buffer = Vec::new();
            if let Ok(_) = sig_file.read_to_end(&mut buffer) {
                // TODO: it looks like Mozilla isn't using a correct COSE signature as per
                // https://github.com/franziskuskiefer/cose-rust/issues/60
                //
                // let maybe_data = CoseSign::from_tagged_slice(&buffer).unwrap();
            }
        }

        Signature {
            name: "COSE".to_string(),
            present: has_cose,
            ..Signature::default()
        }
    }
}

impl fmt::Display for Signatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIGNATURES:\n  {}\n  {}", self.pkcs7, self.cose)
    }
}

fn atv_to_string(atv: &AttributeTypeAndValue) -> String {
    match atv.value.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(&atv.value)
            .unwrap()
            .as_str()
            .to_owned(),
        Tag::Utf8String => Utf8StringRef::try_from(&atv.value)
            .unwrap()
            .as_str()
            .to_owned(),
        _ => "".to_string(),
    }
}