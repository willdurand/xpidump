use json_comments::StripComments;
use serde_json;
use std::{fmt, io};
use zip::ZipArchive;

#[derive(Default)]
pub struct Manifest {
    present: bool,
    pub id: Option<String>,
    pub version: Option<String>,
}

impl Manifest {
    pub fn exists(&self) -> bool {
        self.present
    }

    pub fn parse<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> Manifest {
        match archive.by_name("manifest.json") {
            Ok(file) => {
                // `manifest.json` file may contain comments so we have to strip them first to get
                // a valid JSON document.
                let stripped = StripComments::new(file);
                let data: serde_json::Value = serde_json::from_reader(stripped).unwrap();

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
                            .and_then(|s| Some(s.to_owned()));
                    }
                }

                Manifest {
                    present: true,
                    id: id,
                    version: data
                        .get("version")
                        .and_then(|value| value.as_str())
                        .and_then(|s| Some(s.to_owned())),
                    ..Manifest::default()
                }
            }
            Err(_) => Manifest::default(),
        }
    }
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MANIFEST:\n  ID     : {}\n  Version: {}\n",
            self.id.as_deref().unwrap_or("N/A"),
            self.version.as_deref().unwrap_or("N/A"),
        )
    }
}
