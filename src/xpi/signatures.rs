use super::cose_ish::CoseSign;
use cms::cert::{
    x509::{
        attr::AttributeTypeAndValue,
        certificate::TbsCertificateInner,
        der::{
            asn1::{PrintableStringRef, Utf8StringRef},
            Decode, Encode, Tag, Tagged,
        },
        Certificate,
    },
    CertificateChoices,
};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::{
    rfc4519::{COMMON_NAME, ORGANIZATIONAL_UNIT_NAME},
    rfc5912::{ID_SHA_1, ID_SHA_256},
};
use serde::Serialize;
use std::convert::{From, TryInto};
use std::{fmt, io, io::Read};
use zip::ZipArchive;

#[derive(Default, Serialize)]
/// Represents some of the information found in a certificate.
pub struct CertificateInfo {
    pub common_name: String,
    pub organizational_unit: String,
}

impl CertificateInfo {
    fn is_staging(&self) -> bool {
        self.common_name.contains("staging")
    }
}

impl TryInto<CertificateInfo> for &CertificateChoices {
    type Error = ();

    fn try_into(self) -> Result<CertificateInfo, Self::Error> {
        match self {
            CertificateChoices::Certificate(cert) => Ok((&cert.tbs_certificate).into()),
            _ => Err(()),
        }
    }
}

impl From<&Certificate> for CertificateInfo {
    fn from(value: &Certificate) -> Self {
        (&value.tbs_certificate).into()
    }
}

impl From<&TbsCertificateInner> for CertificateInfo {
    fn from(tbs_cert: &TbsCertificateInner) -> Self {
        let mut common_name = "N/A".to_string();
        let mut organizational_unit = "N/A".to_string();
        for rdn in tbs_cert.subject.0.iter().rev() {
            if let Some(atv) = rdn.0.get(0) {
                match atv.oid {
                    COMMON_NAME => {
                        common_name = atv_to_string(atv);
                    }
                    ORGANIZATIONAL_UNIT_NAME => {
                        organizational_unit = atv_to_string(atv);
                    }
                    _ => {}
                };
            }
        }

        CertificateInfo {
            common_name,
            organizational_unit,
        }
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
/// Represents the kind of signature found in the XPI.
pub enum SignatureKind {
    /// The XPI has been signed as a regular add-on.
    Regular,
    /// The XPI has been signed as a privileged add-on.
    Privileged,
    /// The XPI has been signed as a system add-on.
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

#[derive(Default, Serialize)]
/// Represents a signature found in an [`XPI`](`crate::XPI`).
pub struct Signature {
    present: bool,
    pub algorithm: Option<String>,
    pub certificates: Vec<CertificateInfo>,
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
            "   └── {} / {} / {} / {}\n   └── Certificates:",
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

impl From<CoseSign> for Signature {
    fn from(cs: CoseSign) -> Self {
        Signature {
            present: true,
            algorithm: Some(cs.algorithm),
            certificates: cs
                .certificates
                .into_iter()
                .map(|c: Certificate| (&c).into())
                .collect(),
        }
    }
}

impl From<SignedData> for Signature {
    fn from(data: SignedData) -> Self {
        // TODO: avoid `unwrap()`
        let digest_algorithm = match data.signer_infos.0.get(0).unwrap().digest_alg.oid {
            ID_SHA_1 => "SHA-1",
            ID_SHA_256 => "SHA-256",
            _ => "unknown",
        };

        Signature {
            present: true,
            algorithm: Some(digest_algorithm.to_string()),
            certificates: data
                .certificates
                .map_or(vec![], |certs| certs.0.into_vec())
                .iter()
                .rev()
                .flat_map(|choice| choice.try_into())
                .collect(),
        }
    }
}

#[derive(Serialize)]
/// Represents the set of signatures possibly found in an [`XPI`](`crate::XPI`) file.
pub struct Signatures {
    /// A PKCS#7 signature.
    pub pkcs7: Signature,
    /// A COSEish signature.
    pub cose: Signature,
}

impl Signatures {
    /// Whether there is at least one signature found in the [`XPI`](`crate::XPI`) file.
    pub fn has_signatures(&self) -> bool {
        self.pkcs7.exists() || self.cose.exists()
    }

    pub(crate) fn parse<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Signatures {
        Signatures {
            pkcs7: Signatures::parse_pkcs7(archive),
            cose: Signatures::parse_cose(archive),
        }
    }

    fn parse_pkcs7<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Signature {
        let has_pkcs7_manifest = archive.by_name("META-INF/manifest.mf").is_ok();
        let has_pkcs7_mozilla = archive.by_name("META-INF/mozilla.sf").is_ok();
        let maybe_sig_file = archive.by_name("META-INF/mozilla.rsa");
        let has_pkcs7 = has_pkcs7_manifest && has_pkcs7_mozilla && maybe_sig_file.is_ok();

        if let Ok(mut sig_file) = maybe_sig_file {
            let mut buffer = Vec::new();
            if sig_file.read_to_end(&mut buffer).is_ok() {
                if let Ok(data) = ContentInfo::from_der(&buffer)
                    .and_then(|ci| ci.content.to_der())
                    .and_then(|der| SignedData::from_der(&der))
                {
                    return data.into();
                }
            }
        }

        Signature {
            present: has_pkcs7,
            ..Signature::default()
        }
    }

    fn parse_cose<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Signature {
        let has_cose_manifest = archive.by_name("META-INF/cose.manifest").is_ok();
        let maybe_sig_file = archive.by_name("META-INF/cose.sig");
        let has_cose = has_cose_manifest && maybe_sig_file.is_ok();

        if let Ok(mut sig_file) = maybe_sig_file {
            let mut buffer = Vec::new();
            if sig_file.read_to_end(&mut buffer).is_ok() {
                if let Ok(cs) = CoseSign::parse(&buffer) {
                    return cs.into();
                }
            }
        }

        Signature {
            present: has_cose,
            ..Signature::default()
        }
    }
}

impl fmt::Display for Signatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SIGNATURES:\n  PKCS7:\n{}\n  COSE:\n{}",
            self.pkcs7, self.cose
        )
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
        _ => "???".to_string(),
    }
}
