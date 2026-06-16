use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit},
    Aes128,
};
use aes_gcm::Aes128Gcm;

use crate::Error;

use super::{KEY_SIZE, NONCE_SIZE, SEPARATE_HEADER_SIZE};

const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

pub(super) fn session_cipher(key: &[u8; KEY_SIZE], salt: &[u8]) -> Result<Aes128Gcm, Error> {
    Aes128Gcm::new_from_slice(&session_subkey(key, salt)).map_err(|error| {
        Error::new(
            "outbound-crypto",
            format!("failed initializing Shadowsocks 2022 AEAD cipher: {error:?}"),
        )
    })
}

pub(super) fn encrypt_separate_header(
    key: &[u8; KEY_SIZE],
    separate_header: &[u8; SEPARATE_HEADER_SIZE],
) -> Result<[u8; SEPARATE_HEADER_SIZE], Error> {
    let cipher = block_cipher(key)?;
    let mut block = GenericArray::clone_from_slice(separate_header);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

pub(super) fn decrypt_separate_header(
    key: &[u8; KEY_SIZE],
    encrypted_header: &[u8],
) -> Result<[u8; SEPARATE_HEADER_SIZE], Error> {
    let cipher = block_cipher(key)?;
    let mut block = GenericArray::clone_from_slice(encrypted_header);
    cipher.decrypt_block(&mut block);
    Ok(block.into())
}

pub(super) fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for byte in nonce {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn session_subkey(key: &[u8; KEY_SIZE], salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut material = Vec::with_capacity(key.len() + salt.len());
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key(SESSION_SUBKEY_CONTEXT, &material);
    let mut subkey = [0_u8; KEY_SIZE];
    subkey.copy_from_slice(&derived[..KEY_SIZE]);
    subkey
}

fn block_cipher(key: &[u8; KEY_SIZE]) -> Result<Aes128, Error> {
    Aes128::new_from_slice(key).map_err(|error| {
        Error::new(
            "outbound-crypto",
            format!("failed initializing Shadowsocks 2022 AES block cipher: {error:?}"),
        )
    })
}
