use super::manifest::Manifest;
use super::signatures::Signatures;
use std::{fmt, io};
use zip::ZipArchive;

pub struct XPI {
    pub manifest: Manifest,
    pub signatures: Signatures,
}

impl XPI {
    pub fn new<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>) -> XPI {
        XPI {
            manifest: Manifest::parse(archive),
            signatures: Signatures::parse(archive),
        }
    }
}

impl fmt::Display for XPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.manifest, self.signatures)
    }
}
