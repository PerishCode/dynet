use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit};
use md5::{Digest as Md5Digest, Md5};
use rand::{Rng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN};
use sha2::{Digest as Sha2Digest, Sha256};

const USER_ID_HASH_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

pub(super) fn instruction_key(uuid: &str) -> Result<[u8; 16], String> {
    let mut material = parse_uuid(uuid)?.to_vec();
    material.extend_from_slice(USER_ID_HASH_SUFFIX);
    Ok(md5(&material))
}

pub(super) fn encrypted_auth_id(instruction_key: &[u8; 16]) -> [u8; 16] {
    let mut auth_id = [0_u8; 16];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let random_delta = rand::thread_rng().gen_range(0..=240);
    auth_id[..8].copy_from_slice(&(now.saturating_sub(120) + random_delta).to_be_bytes());
    rand::thread_rng().fill_bytes(&mut auth_id[8..12]);
    let checksum = crc32fast::hash(&auth_id[..12]).to_be_bytes();
    auth_id[12..].copy_from_slice(&checksum);

    let auth_key = kdf(instruction_key, &[b"AES Auth ID Encryption"]);
    let cipher = aes::Aes128::new((&auth_key[..16]).into());
    cipher.encrypt_block((&mut auth_id).into());
    auth_id
}

pub(super) fn seal_header_length(
    header_len: usize,
    instruction_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
) -> Result<Vec<u8>, String> {
    let key = kdf(
        instruction_key,
        &[b"VMess Header AEAD Key_Length", auth_id, nonce],
    );
    let nonce_bytes = kdf(
        instruction_key,
        &[b"VMess Header AEAD Nonce_Length", auth_id, nonce],
    );
    let mut payload = (u16::try_from(header_len)
        .map_err(|_| format!("VMess header too large: {header_len}"))?)
    .to_be_bytes()
    .to_vec();
    seal_aes_gcm(&key[..16], &nonce_bytes[..12], auth_id, &mut payload)?;
    Ok(payload)
}

pub(super) fn seal_header(
    header: &mut Vec<u8>,
    instruction_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
) -> Result<(), String> {
    let key = kdf(instruction_key, &[b"VMess Header AEAD Key", auth_id, nonce]);
    let nonce_bytes = kdf(
        instruction_key,
        &[b"VMess Header AEAD Nonce", auth_id, nonce],
    );
    seal_aes_gcm(&key[..16], &nonce_bytes[..12], auth_id, header)
}

pub(super) fn open_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut [u8],
) -> Result<Vec<u8>, String> {
    let key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| "failed to initialize AES-GCM key".to_string())?;
    let nonce = nonce_from_slice(nonce)?;
    let plaintext = LessSafeKey::new(key)
        .open_in_place(nonce, Aad::from(aad), payload)
        .map_err(|_| "failed to open AES-GCM payload".to_string())?;
    Ok(plaintext.to_vec())
}

pub(super) fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5(key);
    let second = md5(&first);
    let mut output = [0_u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(super) fn first_16(data: &[u8; 32]) -> [u8; 16] {
    data[..16].try_into().expect("slice is exactly 16 bytes")
}

pub(super) fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

pub(super) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut hash: Box<dyn VmessHash> = Box::new(RecursiveHash::new(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash::new()),
    ));
    for item in path {
        hash = Box::new(RecursiveHash::new(item, hash));
    }
    hash.update(key);
    hash.finalize()
}

fn seal_aes_gcm(key: &[u8], nonce: &[u8], aad: &[u8], payload: &mut Vec<u8>) -> Result<(), String> {
    let key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| "failed to initialize AES-GCM key".to_string())?;
    let nonce = nonce_from_slice(nonce)?;
    LessSafeKey::new(key)
        .seal_in_place_append_tag(nonce, Aad::from(aad), payload)
        .map_err(|_| "failed to seal AES-GCM payload".to_string())
}

fn nonce_from_slice(nonce: &[u8]) -> Result<Nonce, String> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| format!("AEAD nonce must be {NONCE_LEN} bytes"))?;
    Ok(Nonce::assume_unique_for_key(nonce))
}

fn parse_uuid(value: &str) -> Result<[u8; 16], String> {
    let compact = value
        .chars()
        .filter(|character| *character != '-')
        .collect::<String>();
    if compact.len() != 32 {
        return Err("VMess uuid must contain 32 hex digits".to_string());
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&compact[start..start + 2], 16)
            .map_err(|error| format!("invalid VMess uuid hex: {error}"))?;
    }
    Ok(bytes)
}

fn md5(data: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    Md5Digest::update(&mut digest, data);
    digest.finalize().into()
}

trait VmessHash {
    fn clone_box(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> [u8; 32];
}

#[derive(Clone)]
struct Sha256Hash(Sha256);

struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
}

impl Sha256Hash {
    fn new() -> Self {
        Self(Sha256::new())
    }
}

impl VmessHash for Sha256Hash {
    fn clone_box(&self) -> Box<dyn VmessHash> {
        Box::new(self.clone())
    }

    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(&mut self.0, data);
    }

    fn finalize(&self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

impl RecursiveHash {
    fn new(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        debug_assert!(key.len() <= 64);
        let mut inner_pad = [0x36_u8; 64];
        let mut outer_pad = [0x5c_u8; 64];
        for (index, byte) in key.iter().enumerate() {
            inner_pad[index] ^= *byte;
            outer_pad[index] ^= *byte;
        }
        let mut inner = hash.clone_box();
        inner.update(&inner_pad);
        Self {
            inner,
            outer: hash,
            inner_pad,
            outer_pad,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn clone_box(&self) -> Box<dyn VmessHash> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            outer: self.outer.clone_box(),
            inner_pad: self.inner_pad,
            outer_pad: self.outer_pad,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&self) -> [u8; 32] {
        let mut outer = self.outer.clone_box();
        outer.update(&self.outer_pad);
        outer.update(&self.inner.finalize());
        outer.finalize()
    }
}
