mod cose_ish;
mod manifest;
mod signatures;

use serde::{Deserialize, Serialize};
use std::{fmt, io};
use zip::ZipArchive;

pub use manifest::*;
pub use signatures::*;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
/// Represents the recommendation state values.
pub enum RecommendationState {
    #[serde(rename = "recommended")]
    /// The XPI is a recommended add-on.
    Recommended,
    #[serde(rename = "recommended-android")]
    /// The XPI is a recommended add-on for Firefox for Android.
    RecommendedAndroid,
    #[serde(rename = "line")]
    /// The XPI is a line add-on.
    Line,
    #[serde(rename = "verified")]
    /// The XPI is a verified add-on.
    Verified,
}

#[derive(Deserialize, Serialize)]
/// Represents the validity of the recommendation state.
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
}

#[derive(Deserialize, Serialize)]
/// Represents the recommendation state of an XPI.
pub struct Recommendation {
    pub schema_version: u64,
    pub addon_id: String,
    pub states: Vec<RecommendationState>,
    pub validity: Validity,
}

#[derive(Serialize)]
/// Represents an XPI file.
///
/// XPI files are very similar to ZIP files and used to package add-ons for Firefox.
pub struct XPI {
    /// Information about the `manifest.json` file.
    pub manifest: Manifest,
    /// Information about the signatures found in the XPI.
    pub signatures: Signatures,
    /// The recommendation state found in the XPI file, if any.
    pub recommendation: Option<Recommendation>,
}

impl XPI {
    /// Constructs a new `XPI` from an instance of
    /// [`ZipArchive`](https://docs.rs/zip/latest/zip/read/struct.ZipArchive.html).
    pub fn new<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> XPI {
        let mut recommendation = None;
        if let Ok(rec_file) = archive.by_name("mozilla-recommendation.json") {
            recommendation = serde_json::from_reader::<_, Recommendation>(rec_file).ok();
        }

        XPI {
            manifest: Manifest::parse(archive),
            signatures: Signatures::parse(archive),
            recommendation,
        }
    }

    /// Whether the XPI is a _recommended_ add-on, i.e. it "looks" signed (i.e. it embeds
    /// signature files) and it has a recommendation state.
    pub fn is_recommended(&self) -> bool {
        self.signatures.has_signatures() && self.recommendation.is_some()
    }
}

impl fmt::Display for XPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let recommendation = if let Some(rec) = &self.recommendation {
            format!("{:?}", rec.states)
        } else {
            "NONE".to_owned()
        };

        write!(
            f,
            "{}\n\nRECOMMENDATION:\n  {}\n\n{}",
            self.manifest, recommendation, self.signatures,
        )
    }
}
