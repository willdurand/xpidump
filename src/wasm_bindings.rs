use crate::{xpi, xpi::signatures::SignatureKind};
use std::io::Cursor;
use wasm_bindgen::prelude::*;
use zip::ZipArchive;

#[wasm_bindgen]
pub struct XPI {
    xpi: xpi::XPI,
}

#[wasm_bindgen]
impl XPI {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>) -> XPI {
        let reader = Cursor::new(data);
        let mut zip_archive = ZipArchive::new(reader).unwrap();

        XPI {
            xpi: xpi::XPI::new(&mut zip_archive),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.xpi.manifest).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn signatures(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.xpi.signatures).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn has_manifest(&self) -> bool {
        self.xpi.manifest.exists()
    }

    #[wasm_bindgen(getter)]
    pub fn is_pkcs7_signed(&self) -> bool {
        self.xpi.signatures.pkcs7.exists()
    }

    #[wasm_bindgen(getter)]
    pub fn is_staging(&self) -> bool {
        self.xpi.signatures.pkcs7.is_staging()
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
    pub fn is_cose_signed(&self) -> bool {
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
