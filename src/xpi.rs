mod cose_ish;
mod manifest;
pub mod signatures;

use crate::xpi::{manifest::Manifest, signatures::Signatures};
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
