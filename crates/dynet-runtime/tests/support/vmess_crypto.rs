use md5::{Digest as Md5Digest, Md5};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN},
    hkdf,
};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub(crate) const AEAD_TAG_LEN: usize = 16;
const KEY_LEN: usize = 16;
const SS_SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];
const USER_ID_HASH_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

pub(crate) fn open_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut [u8],
) -> Result<Vec<u8>, String> {
    let nonce = nonce_from_slice(nonce)?;
    let key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| "failed to initialize AES-GCM key".to_string())?;
    let plaintext = LessSafeKey::new(key)
        .open_in_place(nonce, Aad::from(aad), payload)
        .map_err(|_| "failed to open AES-GCM payload".to_string())?;
    Ok(plaintext.to_vec())
}

pub(crate) fn seal_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Result<(), String> {
    let nonce = nonce_from_slice(nonce)?;
    let key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|_| "failed to initialize AES-GCM key".to_string())?;
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

pub(crate) struct AeadSequence<N> {
    key: LessSafeKey,
    nonce: N,
}

pub(crate) trait NonceSequence {
    fn next(&mut self) -> Nonce;
}

impl<N: NonceSequence> AeadSequence<N> {
    pub(crate) fn new(key: &[u8], nonce: N) -> Result<Self, String> {
        let key = UnboundKey::new(&AES_128_GCM, key)
            .map_err(|_| "failed to initialize response AEAD key".to_string())?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce,
        })
    }

    pub(crate) fn open(&mut self, frame: &mut [u8]) -> Result<Vec<u8>, String> {
        let plaintext = self
            .key
            .open_in_place(self.nonce.next(), Aad::empty(), frame)
            .map_err(|_| "failed to open VMess data frame".to_string())?;
        Ok(plaintext.to_vec())
    }

    pub(crate) fn seal(&mut self, payload: &mut Vec<u8>) -> Result<(), String> {
        self.key
            .seal_in_place_append_tag(self.nonce.next(), Aad::empty(), payload)
            .map_err(|_| "failed to seal response frame".to_string())
    }
}

pub(crate) struct VmessNonce {
    count: u16,
    nonce: [u8; NONCE_LEN],
}

impl VmessNonce {
    pub(crate) fn new(seed: &[u8; 16]) -> Self {
        let mut nonce = [0_u8; NONCE_LEN];
        nonce[2..].copy_from_slice(&seed[2..12]);
        Self { count: 0, nonce }
    }
}

impl NonceSequence for VmessNonce {
    fn next(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        self.count = self.count.wrapping_add(1);
        self.nonce[0] = (self.count >> 8) as u8;
        self.nonce[1] = (self.count & 0xff) as u8;
        nonce
    }
}

#[derive(Default)]
struct FixedNonce {
    bytes: [u8; NONCE_LEN],
}

impl NonceSequence for FixedNonce {
    fn next(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.bytes);
        for byte in &mut self.bytes {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        nonce
    }
}

pub(crate) struct LengthMask {
    reader: Box<dyn XofReader>,
    buffer: [u8; 2],
}

impl LengthMask {
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        Update::update(&mut hasher, seed);
        Self {
            reader: Box::new(hasher.finalize_xof()),
            buffer: [0_u8; 2],
        }
    }

    pub(crate) fn next(&mut self) -> u16 {
        self.reader.read(&mut self.buffer);
        u16::from_be_bytes(self.buffer)
    }
}

pub(crate) fn shadowsocks_response(password: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let salt = [7_u8; KEY_LEN];
    let master_key = password_key(password);
    let session_key = ss_session_key(&master_key, &salt)?;
    let mut sealer = AeadSequence::new(&session_key, FixedNonce::default())?;
    let mut output = salt.to_vec();
    let mut encrypted_len = (payload.len() as u16).to_be_bytes().to_vec();
    sealer.seal(&mut encrypted_len)?;
    let mut encrypted_payload = payload.to_vec();
    sealer.seal(&mut encrypted_payload)?;
    output.extend(encrypted_len);
    output.extend(encrypted_payload);
    Ok(output)
}

pub(crate) fn instruction_key(uuid: &str) -> Result<[u8; 16], String> {
    let mut material = parse_uuid(uuid)?.to_vec();
    material.extend_from_slice(USER_ID_HASH_SUFFIX);
    Ok(md5(&material))
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

fn password_key(password: &str) -> Vec<u8> {
    let password = password.as_bytes();
    let mut output = Vec::new();
    let mut previous = Vec::new();
    while output.len() < KEY_LEN {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            Md5Digest::update(&mut digest, &previous);
        }
        Md5Digest::update(&mut digest, password);
        previous = digest.finalize().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(KEY_LEN);
    output
}

fn ss_session_key(master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = vec![0_u8; KEY_LEN];
    hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(master_key)
        .expand(SS_SUBKEY_INFO, KeyLen(KEY_LEN))
        .map_err(|_| "failed to expand SS session key".to_string())?
        .fill(&mut output)
        .map_err(|_| "failed to fill SS session key".to_string())?;
    Ok(output)
}

struct KeyLen(usize);

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn md5(data: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    Md5Digest::update(&mut digest, data);
    digest.finalize().into()
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn first_16(data: &[u8; 32]) -> [u8; 16] {
    data[..16].try_into().expect("slice is exactly 16 bytes")
}

pub(crate) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
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
