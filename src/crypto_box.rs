use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, Result};

const HKDF_SALT: &[u8] = b"arkret-aead-seal-hkdf-v1";
const NONCE_LEN: usize = 24;

fn derive_key(key_material: &[u8], aad: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), key_material);
    let mut key = [0u8; 32];
    hkdf.expand(aad, &mut key)
        .map_err(|_| Error::Crypto("AEAD key derivation failed".to_owned()))?;
    Ok(key)
}

pub(crate) fn seal(plaintext: &[u8], key_material: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key(key_material, aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Crypto("AEAD cipher initialization failed".to_owned()))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| Error::Crypto(error.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("AEAD encryption failed".to_owned()))?;
    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}
