use crate::{Environment, SignatureKind, XPI as InnerXPI};
use std::io::Cursor;
use wasm_bindgen::prelude::*;
use zip::ZipArchive;

// This file contains a thin layer to expose the `xpidump` information in a WASM environment.

#[wasm_bindgen]
pub struct XPI {
    xpi: InnerXPI,
}

#[wasm_bindgen]
impl XPI {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>) -> XPI {
        let reader = Cursor::new(data);
        let mut zip_archive = ZipArchive::new(reader).unwrap();

        XPI {
            xpi: InnerXPI::new(&mut zip_archive),
        }
    }

    #[wasm_bindgen]
    pub fn to_js(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.xpi).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.xpi.manifest).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn has_manifest(&self) -> bool {
        self.xpi.manifest.exists()
    }

    #[wasm_bindgen(getter)]
    pub fn has_pkcs7_sig(&self) -> bool {
        self.xpi.signatures.pkcs7.exists()
    }

    #[wasm_bindgen(getter)]
    pub fn env(&self) -> String {
        match self.xpi.signatures.pkcs7.env() {
            Environment::Unknown => "unknown".to_string(),
            Environment::Development => "development".to_string(),
            Environment::Staging => "staging".to_string(),
            Environment::Production => "production".to_string(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pkcs7_algorithm(&self) -> String {
        self.xpi
            .signatures
            .pkcs7
            .algorithm
            .as_deref()
            .unwrap_or("")
            .to_owned()
    }

    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        match self.xpi.signatures.pkcs7.kind() {
            SignatureKind::Regular => "regular".to_string(),
            SignatureKind::Privileged => "privileged".to_string(),
            SignatureKind::System => "system".to_string(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn has_cose_sig(&self) -> bool {
        self.xpi.signatures.cose.exists()
    }

    #[wasm_bindgen(getter)]
    pub fn cose_algorithm(&self) -> String {
        self.xpi
            .signatures
            .cose
            .algorithm
            .as_deref()
            .unwrap_or("")
            .to_owned()
    }
}
