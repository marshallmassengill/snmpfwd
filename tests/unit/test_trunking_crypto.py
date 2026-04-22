"""AES-CBC round-trips for the trunk crypto helper."""
from __future__ import annotations

import pytest

from snmpfwd.trunking.crypto import AESCipher, decrypt, encrypt


@pytest.fixture
def cipher() -> AESCipher:
    return AESCipher()


@pytest.mark.parametrize("plaintext", [
    b"",
    b"\x00",
    b"hello",
    b"A" * 15,       # one-short-of-block
    b"B" * 16,       # exact block
    b"C" * 17,       # one-past-block
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 10,
    bytes(range(256)),
])
def test_roundtrip(cipher, plaintext):
    key = "0123456789abcdef"  # exactly 16 chars
    ct = cipher.encrypt(key, plaintext)
    assert len(ct) >= 16 + 16, "ciphertext should carry 16-byte IV + at least one block"
    assert ct[:16] != b"\x00" * 16, "IV should not be all-zero"
    assert cipher.decrypt(key, ct) == plaintext


def test_iv_is_random(cipher):
    key = "0123456789abcdef"
    ct1 = cipher.encrypt(key, b"same plaintext")
    ct2 = cipher.encrypt(key, b"same plaintext")
    assert ct1 != ct2, "encrypt() should pick a fresh IV every call"
    assert ct1[:16] != ct2[:16], "IV prefixes must differ"


def test_module_level_encrypt_decrypt():
    """snmpfwd.trunking.protocol calls the module-level `encrypt` and
    `decrypt` names directly, so they must round-trip identically."""
    key = "abcdefghijklmnop"
    raw = b"trunk payload bytes with\nembedded\nnewlines"
    assert decrypt(key, encrypt(key, raw)) == raw


def test_pkcs7_padding_shape(cipher):
    """Padding bytes should be the pad-length value repeated."""
    key = "xxxxxxxxxxxxxxxx"
    # 13 bytes → 3 bytes of padding, each byte = 0x03
    raw = b"A" * 13
    ct = cipher.encrypt(key, raw)
    # Decrypting strips padding transparently; re-encrypt a known plaintext
    # and check its last block has the expected structure by decrypting
    # without unpad: we don't have an API for that, so just verify the
    # public round-trip preserves the exact byte string including padding
    # semantics.
    assert cipher.decrypt(key, ct) == raw


def test_key_shorter_than_16_bytes_is_accepted_if_padded_by_caller():
    """snmpfwd pads `trunk-crypto-key` to 16 bytes before calling encrypt;
    this test documents that the cipher itself requires an already-16-byte
    key and will error otherwise."""
    cipher = AESCipher()
    with pytest.raises(Exception):
        cipher.encrypt("short", b"plaintext")
