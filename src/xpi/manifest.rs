use json_comments::StripComments;
use serde::Serialize;
use serde_json;
use std::{fmt, io};
use zip::ZipArchive;

#[derive(Default, Serialize)]
/// Represents the information contained in the `manifest.json` file.
pub struct Manifest {
    present: bool,
    /// The add-on ID found in the manifest, if any.
    pub id: Option<String>,
    /// The add-on version found in the manifest file, if any.
    pub version: Option<String>,
}

impl Manifest {
    pub(crate) fn parse<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Manifest {
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
                        }
                    }
                    Err(_) => Manifest::default(),
                }
            }
            Err(_) => Manifest::default(),
        }
    }

    /// Indicates whether the `manifest.json` file exists in the XPI.
    pub fn exists(&self) -> bool {
        self.present
    }
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MANIFEST:\n  ID     : {}\n  Version: {}",
            self.id.as_deref().unwrap_or("N/A"),
            self.version.as_deref().unwrap_or("N/A"),
        )
    }
}
