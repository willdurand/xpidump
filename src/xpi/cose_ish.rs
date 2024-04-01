use minicbor::data::Int;
use minicbor::decode::Decoder;
use std::convert::From;
use x509_cert;
use x509_cert::der::Decode;

const COSE_SIGN_TAG: u64 = 98;
const COSE_ALG: u64 = 1;
const COSE_KID: u64 = 4;

pub enum CoseError {
    InvalidTag,
    UnexpectedType,
    MalformedInput,
}

impl From<minicbor::decode::Error> for CoseError {
    fn from(_: minicbor::decode::Error) -> Self {
        CoseError::UnexpectedType
    }
}

pub struct CoseSign {
    pub algorithm: String,
    pub certificates: Vec<x509_cert::Certificate>,
}

impl CoseSign {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, CoseError> {
        let mut decoder = Decoder::new(bytes);

        if decoder.tag()?.as_u64() != COSE_SIGN_TAG {
            return Err(CoseError::InvalidTag);
        }

        // We expect an array with 4 entries:
        //
        // COSE_Sign = [
        //   protected : serialized_map,
        //   unprotected : header_map
        //   payload : nil,
        //   signatures : [COSE_Signature, ...]
        // ]
        //
        match decoder.array()? {
            Some(4) => {}
            _ => return Err(CoseError::MalformedInput),
        };

        // protected should contain the intermediate certificates.
        let mut certificates = vec![];
        let protected = decoder.bytes()?;
        let mut dec = Decoder::new(protected);
        // We expect a map with an array in it.
        match dec.map()? {
            Some(1) => {}
            _ => return Err(CoseError::MalformedInput),
        };

        if dec.int()? == Int::from(COSE_KID) {
            // Important: this is no RFC 8152 compliant because `kid` should be `bstr`, not an
            // `array`. See: https://github.com/franziskuskiefer/cose-rust/issues/60
            let size = match dec.array()? {
                Some(size) => size,
                None => return Err(CoseError::MalformedInput),
            };

            // Decode all the intermediate certificates.
            for _ in 0..size {
                let data = dec.bytes()?;
                if let Ok(cert) = x509_cert::Certificate::from_der(data) {
                    certificates.push(cert);
                }
            }
        }

        // unprotected should be an empty map.
        match decoder.map()? {
            Some(0) => {}
            _ => return Err(CoseError::MalformedInput),
        };

        // payload should be null because this is a detached signature.
        decoder.null()?;

        // signatures
        let mut algorithm: String = "UNKNOWN".to_owned();
        let size = match decoder.array()? {
            Some(size) => size,
            None => return Err(CoseError::MalformedInput),
        };
        for _ in 0..size {
            // COSE_Signature =  [
            //   protected : serialized_map,
            //   unprotected : header_map
            //   signature : bstr
            // ]
            match decoder.array()? {
                Some(3) => {}
                _ => return Err(CoseError::MalformedInput),
            };

            let protected = decoder.bytes()?;
            let mut dec = Decoder::new(protected);
            // We expect a map with 2 entries: `alg` and `kid`.
            match dec.map()? {
                Some(2) => {}
                _ => return Err(CoseError::MalformedInput),
            };

            if dec.int()? == Int::from(COSE_ALG) {
                let val = dec.int()?;
                algorithm = if val == Int::from(-7) {
                    "ES256".to_owned()
                } else if val == Int::from(-35) {
                    "ES384".to_owned()
                } else if val == Int::from(-36) {
                    "ES512".to_owned()
                } else {
                    algorithm
                };
            }

            if dec.int()? == Int::from(COSE_KID) {
                let data = dec.bytes()?;
                if let Ok(cert) = x509_cert::Certificate::from_der(data) {
                    certificates.push(cert);
                }
            }

            // unprotected
            decoder.map()?;
            // signature
            decoder.bytes()?;
        }

        Ok(CoseSign {
            algorithm,
            certificates,
        })
    }
}
