//! A library to parse XPI files.
//!
//! # Example
//!
//! ```
//! use std::fs;
//! use xpidump::XPI;
//! use zip::ZipArchive;
//!
//! let mut archive = ZipArchive::new(
//!   fs::File::open("tests/fixtures/dev-new.xpi").unwrap()
//! ).unwrap();
//! let xpi = XPI::new(&mut archive);
//!
//! println!("Add-on ID in the manifest: {}", xpi.manifest.id.unwrap());
//! // Add-on ID in the manifest: {c208c857-c691-4c69-bfa9-3c2b04f4a0ec}
//! ```
mod xpi;

pub use xpi::*;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;
