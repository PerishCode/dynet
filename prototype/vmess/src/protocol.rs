use std::{net::SocketAddr, time::SystemTime};

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as BlockKeyInit},
    Aes128,
};
use aes_gcm::{aead::Aead, Aes128Gcm, Nonce};
use crc32fast::Hasher as Crc32;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use crate::Error;

type HmacSha256 = Hmac<Sha256>;

const VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
pub(crate) const RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub(crate) const RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub(crate) const RESP_HEADER_KEY: &[u8] = b"AEAD Resp Header Key";
pub(crate) const RESP_HEADER_IV: &[u8] = b"AEAD Resp Header IV";
pub(crate) const AEAD_TAG_SIZE: usize = 16;
const OPTION_STANDARD_CHUNK: u8 = 0x01;
const SECURITY_AES_128_GCM: u8 = 0x03;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RequestContext {
    pub(crate) request_iv: [u8; 16],
    pub(crate) request_key: [u8; 16],
    pub(crate) response_auth: u8,
}

pub(crate) fn request_context() -> RequestContext {
    RequestContext {
        request_iv: random_16(),
        request_key: random_16(),
        response_auth: random_1(),
    }
}

pub(crate) fn request(
    cmd_key: &[u8; 16],
    command: u8,
    target: SocketAddr,
    context: &RequestContext,
) -> Result<Vec<u8>, Error> {
    let auth_id = auth_id(cmd_key)?;
    let nonce = random_8();
    let header = instruction_header(command, target, context);
    let encrypted_length = encrypt_header_length(cmd_key, &auth_id, &nonce, header.len())?;
    let encrypted_header = encrypt_header(cmd_key, &auth_id, &nonce, &header)?;
    Ok([
        auth_id.as_slice(),
        encrypted_length.as_slice(),
        nonce.as_slice(),
        encrypted_header.as_slice(),
    ]
    .concat())
}

pub(crate) fn encrypt_chunk(
    key: &[u8; 16],
    iv: &[u8; 16],
    counter: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let ciphertext = encrypt_aead(key, &chunk_nonce(counter, iv), &[], payload)?;
    let length = u16::try_from(ciphertext.len())
        .map_err(|_| Error::new("outbound-protocol", "VMess encrypted chunk is too large"))?;
    let mut packet = Vec::with_capacity(2 + ciphertext.len());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

pub(crate) fn decrypt_chunk(
    key: &[u8; 16],
    iv: &[u8; 16],
    counter: u16,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    decrypt_aead(key, &chunk_nonce(counter, iv), &[], ciphertext)
}

pub(crate) fn decrypt_response_length(
    key: &[u8; 16],
    iv: &[u8; 16],
    packet: &[u8],
) -> Result<Vec<u8>, Error> {
    let length_key = kdf16(key, &[RESP_LEN_KEY]);
    let length_iv = kdf12(iv, &[RESP_LEN_IV]);
    decrypt_aead(&length_key, &length_iv, &[], packet)
}

pub(crate) fn decrypt_response_header(
    key: &[u8; 16],
    iv: &[u8; 16],
    packet: &[u8],
) -> Result<Vec<u8>, Error> {
    let header_key = kdf16(key, &[RESP_HEADER_KEY]);
    let header_iv = kdf12(iv, &[RESP_HEADER_IV]);
    decrypt_aead(&header_key, &header_iv, &[], packet)
}

pub(crate) fn command_key(user_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(user_id);
    hasher.update(CMD_KEY_SALT);
    hasher.finalize().into()
}

pub(crate) fn sha256_16(input: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    digest[..16].try_into().expect("digest has 16 bytes")
}

fn auth_id(cmd_key: &[u8; 16]) -> Result<[u8; 16], Error> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| Error::new("outbound-protocol", format!("invalid system time: {error}")))?
        .as_secs();
    let mut plaintext = [0_u8; 16];
    plaintext[..8].copy_from_slice(&timestamp.to_be_bytes());
    OsRng.fill_bytes(&mut plaintext[8..12]);
    let mut crc = Crc32::new();
    crc.update(&plaintext[..12]);
    plaintext[12..].copy_from_slice(&crc.finalize().to_be_bytes());

    let key = kdf16(cmd_key, &[AUTH_ID_KEY]);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&plaintext);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

fn encrypt_header_length(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    length: usize,
) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(length)
        .map_err(|_| Error::new("outbound-protocol", "VMess header is too large"))?;
    let key = kdf16(cmd_key, &[HEADER_LEN_KEY, auth_id, nonce]);
    let iv = kdf12(cmd_key, &[HEADER_LEN_IV, auth_id, nonce]);
    encrypt_aead(&key, &iv, auth_id, &length.to_be_bytes())
}

fn encrypt_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    header: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = kdf16(cmd_key, &[HEADER_KEY, auth_id, nonce]);
    let iv = kdf12(cmd_key, &[HEADER_IV, auth_id, nonce]);
    encrypt_aead(&key, &iv, auth_id, header)
}

fn instruction_header(command: u8, target: SocketAddr, context: &RequestContext) -> Vec<u8> {
    let mut header = Vec::with_capacity(1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 16 + 4);
    header.push(1);
    header.extend_from_slice(&context.request_iv);
    header.extend_from_slice(&context.request_key);
    header.push(context.response_auth);
    header.push(OPTION_STANDARD_CHUNK);
    header.push(SECURITY_AES_128_GCM);
    header.push(0);
    header.push(command);
    write_address(target, &mut header);
    let checksum = fnv1a(&header);
    header.extend_from_slice(&checksum.to_be_bytes());
    header
}

fn write_address(target: SocketAddr, output: &mut Vec<u8>) {
    output.extend_from_slice(&target.port().to_be_bytes());
    match target {
        SocketAddr::V4(address) => {
            output.push(0x01);
            output.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            output.push(0x03);
            output.extend_from_slice(&address.ip().octets());
        }
    }
}

fn chunk_nonce(counter: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

pub(crate) fn validate_response_header(response_auth: u8, header: &[u8]) -> Result<(), Error> {
    if header.len() < 4 {
        return Err(Error::new(
            "outbound-protocol",
            "truncated VMess response header",
        ));
    }
    if header[0] != response_auth {
        return Err(Error::new(
            "outbound-protocol",
            "VMess response auth mismatch",
        ));
    }
    let command_length = usize::from(header[3]);
    if header.len() != 4 + command_length {
        return Err(Error::new(
            "outbound-protocol",
            "invalid VMess response command length",
        ));
    }
    Ok(())
}

fn encrypt_aead(
    key: &[u8; 16],
    nonce: &[u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|error| {
        Error::new(
            "outbound-crypto",
            format!("failed initializing VMess AEAD cipher: {error:?}"),
        )
    })?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|error| {
            Error::new(
                "outbound-crypto",
                format!("VMess AEAD encrypt failed: {error:?}"),
            )
        })
}

fn decrypt_aead(
    key: &[u8; 16],
    nonce: &[u8; 12],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|error| {
        Error::new(
            "outbound-crypto",
            format!("failed initializing VMess AEAD cipher: {error:?}"),
        )
    })?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|error| {
            Error::new(
                "outbound-crypto",
                format!("VMess AEAD decrypt failed: {error:?}"),
            )
        })
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let digest = kdf(key, path);
    digest[..16].try_into().expect("digest has 16 bytes")
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let digest = kdf(key, path);
    digest[..12].try_into().expect("digest has 12 bytes")
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(VMESS_AEAD_KDF);
    keys.extend_from_slice(path);
    nested_hmac(&keys, key)
}

fn nested_hmac(keys: &[&[u8]], message: &[u8]) -> [u8; 32] {
    match keys {
        [key] => {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts key");
            mac.update(message);
            mac.finalize().into_bytes().into()
        }
        [parents @ .., key] => hmac_with_hash(|input| nested_hmac(parents, input), key, message),
        [] => unreachable!("KDF always has a root key"),
    }
}

fn hmac_with_hash(hash: impl Fn(&[u8]) -> [u8; 32], key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut normalized_key = if key.len() > 64 {
        hash(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(64, 0);

    let mut inner = Vec::with_capacity(64 + message.len());
    for byte in &normalized_key {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = hash(&inner);

    let mut outer = Vec::with_capacity(64 + inner_hash.len());
    for byte in &normalized_key {
        outer.push(byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

fn fnv1a(input: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in input {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn random_16() -> [u8; 16] {
    let mut value = [0_u8; 16];
    OsRng.fill_bytes(&mut value);
    value
}

fn random_8() -> [u8; 8] {
    let mut value = [0_u8; 8];
    OsRng.fill_bytes(&mut value);
    value
}

fn random_1() -> u8 {
    let mut value = [0_u8; 1];
    OsRng.fill_bytes(&mut value);
    value[0]
}
