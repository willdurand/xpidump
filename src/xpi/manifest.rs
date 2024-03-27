use json_comments::StripComments;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{fmt, io};
use zip::ZipArchive;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum RecommendationState {
    #[serde(rename = "recommended")]
    Recommended,
    #[serde(rename = "recommended-android")]
    RecommendedAndroid,
    #[serde(rename = "line")]
    Line,
    #[serde(rename = "verified")]
    Verified,
}

#[derive(Deserialize, Serialize)]
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
}

#[derive(Deserialize, Serialize)]
pub struct Recommendation {
    pub schema_version: u64,
    pub addon_id: String,
    pub states: Vec<RecommendationState>,
    pub validity: Validity,
}

#[derive(Default, Serialize)]
pub struct Manifest {
    present: bool,
    pub id: Option<String>,
    pub version: Option<String>,
    pub recommendation: Option<Recommendation>,
}

impl Manifest {
    pub fn parse<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Manifest {
        let mut recommendation = None;
        if let Ok(rec_file) = archive.by_name("mozilla-recommendation.json") {
            recommendation = serde_json::from_reader::<_, Recommendation>(rec_file).ok();
        }

        match archive.by_name("manifest.json") {
            Ok(file) => {
                // `manifest.json` file may contain comments so we have to strip them first to get
                // a valid JSON document.
                let stripped = StripComments::new(file);
                match serde_json::from_reader::<_, serde_json::Value>(stripped) {
                    Ok(data) => {
                        // Retrieve the add-on ID from the manifest.
                        let mut id = None;
                        if let Some(bss) = data
                            .get("browser_specific_settings")
                            .or(data.get("applications"))
                        {
                            if let Some(gecko) = bss.get("gecko") {
                                id = gecko
                                    .get("id")
                                    .and_then(|value| value.as_str())
                                    .map(|s| s.to_owned());
                            }
                        }

                        Manifest {
                            present: true,
                            id,
                            version: data
                                .get("version")
                                .and_then(|value| value.as_str())
                                .map(|s| s.to_owned()),
                            recommendation,
                        }
                    }
                    Err(_) => Manifest::default(),
                }
            }
            Err(_) => Manifest::default(),
        }
    }

    pub fn exists(&self) -> bool {
        self.present
    }

    pub fn is_recommended(&self) -> bool {
        self.recommendation.is_some()
    }
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let recommendation = if let Some(rec) = &self.recommendation {
            format!("{:?}", rec.states)
        } else {
            "NONE".to_owned()
        };

        write!(
            f,
            "MANIFEST:\n  ID            : {}\n  Version       : {}\n  Recommendation: {}\n",
            self.id.as_deref().unwrap_or("N/A"),
            self.version.as_deref().unwrap_or("N/A"),
            recommendation,
        )
    }
}
