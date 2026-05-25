from __future__ import annotations


REMOTE_OWNED_PRIVATE_SERVER = r"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time

TAG_LEN = 16
KEY_LEN = 16
NONCE_LEN = 12
MAX_PAYLOAD_LEN = 0x3FFF
SS_SUBKEY_INFO = b"ss-subkey"
REMOTE_SCHEMA = "dynet-owned-private-remote/v1alpha1"
EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11


def load_crypto():
    lib = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so")
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_128_gcm.restype = ctypes.c_void_p
    for name in ["EVP_EncryptInit_ex", "EVP_DecryptInit_ex"]:
        getattr(lib, name).argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
    for name in ["EVP_EncryptUpdate", "EVP_DecryptUpdate"]:
        getattr(lib, name).argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int,
        ]
    for name in ["EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex"]:
        getattr(lib, name).argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    return lib


CRYPTO = load_crypto()


class Nonce:
    def __init__(self) -> None:
        self.value = bytearray(NONCE_LEN)

    def next(self) -> bytes:
        output = bytes(self.value)
        for index, byte in enumerate(self.value):
            self.value[index] = (byte + 1) & 0xFF
            if byte != 0xFF:
                break
        return output


def cbuf(value: bytes):
    return ctypes.create_string_buffer(value, len(value))


def aes_gcm_seal(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ctx = CRYPTO.EVP_CIPHER_CTX_new()
    output = ctypes.create_string_buffer(len(plaintext) + TAG_LEN)
    output_len = ctypes.c_int()
    final_len = ctypes.c_int()
    try:
        check(CRYPTO.EVP_EncryptInit_ex(ctx, CRYPTO.EVP_aes_128_gcm(), None, None, None))
        check(CRYPTO.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None))
        key_buffer = cbuf(key)
        nonce_buffer = cbuf(nonce)
        input_buffer = cbuf(plaintext)
        check(CRYPTO.EVP_EncryptInit_ex(ctx, None, None, key_buffer, nonce_buffer))
        check(
            CRYPTO.EVP_EncryptUpdate(
                ctx,
                output,
                ctypes.byref(output_len),
                input_buffer,
                len(plaintext),
            )
        )
        check(
            CRYPTO.EVP_EncryptFinal_ex(
                ctx,
                ctypes.byref(output, output_len.value),
                ctypes.byref(final_len),
            )
        )
        tag = ctypes.create_string_buffer(TAG_LEN)
        check(CRYPTO.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        end = output_len.value + final_len.value
        return output.raw[:end] + tag.raw
    finally:
        CRYPTO.EVP_CIPHER_CTX_free(ctx)


def aes_gcm_open(key: bytes, nonce: bytes, encrypted: bytes) -> bytes:
    if len(encrypted) < TAG_LEN:
        raise ValueError("encrypted payload shorter than tag")
    ciphertext = encrypted[:-TAG_LEN]
    tag = encrypted[-TAG_LEN:]
    ctx = CRYPTO.EVP_CIPHER_CTX_new()
    output = ctypes.create_string_buffer(len(ciphertext) + TAG_LEN)
    output_len = ctypes.c_int()
    final_len = ctypes.c_int()
    try:
        check(CRYPTO.EVP_DecryptInit_ex(ctx, CRYPTO.EVP_aes_128_gcm(), None, None, None))
        check(CRYPTO.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(nonce), None))
        key_buffer = cbuf(key)
        nonce_buffer = cbuf(nonce)
        input_buffer = cbuf(ciphertext)
        check(CRYPTO.EVP_DecryptInit_ex(ctx, None, None, key_buffer, nonce_buffer))
        check(
            CRYPTO.EVP_DecryptUpdate(
                ctx,
                output,
                ctypes.byref(output_len),
                input_buffer,
                len(ciphertext),
            )
        )
        tag_buffer = cbuf(tag)
        check(CRYPTO.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag_buffer))
        if CRYPTO.EVP_DecryptFinal_ex(
            ctx,
            ctypes.byref(output, output_len.value),
            ctypes.byref(final_len),
        ) != 1:
            raise ValueError("AES-GCM tag verification failed")
        end = output_len.value + final_len.value
        return output.raw[:end]
    finally:
        CRYPTO.EVP_CIPHER_CTX_free(ctx)


def check(value: int) -> None:
    if value != 1:
        raise RuntimeError("OpenSSL EVP call failed")


def password_key(password: str) -> bytes:
    output = b""
    previous = b""
    material = password.encode("utf-8")
    while len(output) < KEY_LEN:
        previous = hashlib.md5(previous + material).digest()
        output += previous
    return output[:KEY_LEN]


def session_key(master_key: bytes, salt: bytes) -> bytes:
    prk = hmac.new(salt, master_key, hashlib.sha1).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < KEY_LEN:
        previous = hmac.new(
            prk,
            previous + SS_SUBKEY_INFO + bytes([counter]),
            hashlib.sha1,
        ).digest()
        output += previous
        counter += 1
    return output[:KEY_LEN]


def read_exact(stream: socket.socket, length: int, label: str) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError(f"unexpected EOF while reading {label}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_chunk(stream: socket.socket, key: bytes, nonce: Nonce) -> bytes:
    encrypted_len = read_exact(stream, 2 + TAG_LEN, "SS chunk length")
    length_plain = aes_gcm_open(key, nonce.next(), encrypted_len)
    if len(length_plain) != 2:
        raise ValueError("invalid SS chunk length plaintext")
    payload_len = int.from_bytes(length_plain, "big")
    if payload_len > MAX_PAYLOAD_LEN:
        raise ValueError("SS chunk length too large")
    encrypted_payload = read_exact(stream, payload_len + TAG_LEN, "SS chunk payload")
    return aes_gcm_open(key, nonce.next(), encrypted_payload)


def seal_chunk(key: bytes, nonce: Nonce, payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD_LEN:
        raise ValueError("SS response chunk too large")
    length = len(payload).to_bytes(2, "big")
    return aes_gcm_seal(key, nonce.next(), length) + aes_gcm_seal(key, nonce.next(), payload)


def ss_response(password: str, payload: bytes) -> bytes:
    salt = os.urandom(KEY_LEN)
    key = session_key(password_key(password), salt)
    return salt + seal_chunk(key, Nonce(), payload)


def parse_target(payload: bytes):
    if not payload:
        raise ValueError("empty SS request payload")
    kind = payload[0]
    if kind == 1:
        if len(payload) < 7:
            raise ValueError("truncated IPv4 target")
        host = ".".join(str(item) for item in payload[1:5])
        port = int.from_bytes(payload[5:7], "big")
        return host, port, "ipv4", 7
    if kind == 3:
        if len(payload) < 2:
            raise ValueError("missing domain target length")
        length = payload[1]
        end = 2 + length
        if len(payload) < end + 2:
            raise ValueError("truncated domain target")
        host = payload[2:end].decode("utf-8", "replace")
        port = int.from_bytes(payload[end : end + 2], "big")
        return host, port, "domain", end + 2
    if kind == 4:
        if len(payload) < 19:
            raise ValueError("truncated IPv6 target")
        parts = [payload[index : index + 2].hex() for index in range(1, 17, 2)]
        host = ":".join(parts)
        port = int.from_bytes(payload[17:19], "big")
        return host, port, "ipv6", 19
    raise ValueError(f"unsupported SS address type {kind}")


class EchoTarget:
    def __init__(self, expected: int, timeout: float, reply: bytes) -> None:
        self.expected = expected
        self.timeout = timeout
        self.reply = reply
        self.rows = []
        self.errors = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("0.0.0.0", 0))
        self.listener.listen(max(1, expected))
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        deadline = time.monotonic() + self.timeout
        try:
            while len(self.rows) < self.expected and time.monotonic() < deadline:
                self.listener.settimeout(max(0.1, min(1.0, deadline - time.monotonic())))
                try:
                    conn, _peer = self.listener.accept()
                except socket.timeout:
                    continue
                self.handle(conn)
        except OSError as error:
            self.errors.append(str(error))
        finally:
            self.listener.close()

    def handle(self, conn: socket.socket) -> None:
        row = {"index": len(self.rows) + 1}
        try:
            with conn:
                conn.settimeout(3.0)
                data = conn.recv(4096)
                row["receivedBytes"] = len(data)
                row["tlsClientHelloLike"] = data.startswith(b"\x16\x03")
                sent = 0
                if self.reply:
                    sent = conn.send(self.reply)
                row["sentBytes"] = sent
        except OSError as error:
            row["errorType"] = type(error).__name__
        self.rows.append(row)


class OwnedPrivate:
    def __init__(self, expected: int, timeout: float, password: str) -> None:
        self.expected = expected
        self.timeout = timeout
        self.password = password
        self.rows = []
        self.errors = []
        self.listener = None
        self.port = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        if expected:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(("0.0.0.0", 0))
            self.listener.listen(max(1, expected))
            self.port = self.listener.getsockname()[1]

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        if self.listener is None:
            return
        deadline = time.monotonic() + self.timeout
        try:
            while len(self.rows) < self.expected and time.monotonic() < deadline:
                self.listener.settimeout(max(0.1, min(1.0, deadline - time.monotonic())))
                try:
                    conn, _peer = self.listener.accept()
                except socket.timeout:
                    continue
                self.handle(conn)
        except OSError as error:
            self.errors.append(str(error))
        finally:
            self.listener.close()

    def handle(self, conn: socket.socket) -> None:
        row = {"index": len(self.rows) + 1}
        try:
            with conn:
                conn.settimeout(5.0)
                salt = read_exact(conn, KEY_LEN, "SS request salt")
                key = session_key(password_key(self.password), salt)
                payload = read_chunk(conn, key, Nonce())
                host, port, target_type, offset = parse_target(payload)
                initial = payload[offset:]
                row.update(
                    {
                        "decoded": True,
                        "targetType": target_type,
                        "targetHostLength": len(host),
                        "targetPort": port,
                        "initialPayloadBytes": len(initial),
                        "tlsClientHelloLike": initial.startswith(b"\x16\x03"),
                    }
                )
                target = socket.create_connection((host, port), timeout=4.0)
                with target:
                    target.settimeout(3.0)
                    target.sendall(initial)
                    row["targetConnected"] = True
                    row["targetWriteBytes"] = len(initial)
                    try:
                        response = target.recv(4096)
                    except socket.timeout:
                        response = b""
                    row["targetReadBytes"] = len(response)
                if response:
                    encrypted = ss_response(self.password, response)
                    conn.sendall(encrypted)
                    row["responseSentBytes"] = len(encrypted)
                else:
                    row["responseSentBytes"] = 0
        except Exception as error:
            row["decoded"] = bool(row.get("decoded"))
            row["errorType"] = type(error).__name__
            row["error"] = str(error)
        self.rows.append(row)


def main() -> None:
    private_expected = int(sys.argv[1])
    target_expected = int(sys.argv[2])
    timeout = float(sys.argv[3])
    password = sys.argv[4]
    reply = sys.argv[5].encode("utf-8")
    target = EchoTarget(target_expected, timeout, reply)
    private = OwnedPrivate(private_expected, timeout, password)
    target.start()
    private.start()
    print(
        json.dumps(
            {
                "ready": True,
                "privatePort": private.port,
                "targetPort": target.port,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    private.thread.join(timeout + 2.0)
    target.thread.join(timeout + 2.0)
    print(
        json.dumps(
            {
                "schema": REMOTE_SCHEMA,
                "status": "completed",
                "expectedPrivateConnections": private_expected,
                "expectedTargetConnections": target_expected,
                "privateListenPort": private.port,
                "targetListenPort": target.port,
                "privateConnections": private.rows,
                "targetConnections": target.rows,
                "errors": {
                    "private": private.errors,
                    "target": target.errors,
                },
                "privacy": {
                    "rawPayloadStored": False,
                    "peerAddressStored": False,
                    "targetHostStored": False,
                },
            },
            sort_keys=True,
        ),
        flush=True,
    )


main()
"""
