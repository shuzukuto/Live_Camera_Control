"""
Unit Tests for AES-256-GCM AEAD Credential Vault (backend/app/vault.py)
"""

import os
import base64
import pytest
from pathlib import Path

from app.vault import (
    VaultManager,
    VaultError,
    VaultConfigurationError,
    VaultDecryptionError,
    get_vault,
    init_vault,
    is_vault_initialized,
    encrypt_secret,
    decrypt_secret,
    encrypt_json,
    decrypt_json,
    mask_secret,
)


@pytest.fixture(autouse=True)
def clean_vault_singleton(tmp_path):
    """Ensure a fresh, isolated VaultManager for each test."""
    VaultManager.reset_instance()
    vault = VaultManager.get_instance()
    salt_file = tmp_path / ".test_salt"
    key_file = tmp_path / ".test_key"
    vault.initialize(
        passphrase="TestMasterPassphrase_2026!#",
        salt_path=salt_file,
        master_key_file=key_file,
        iterations=10_000,  # Fast iterations for test speed
    )
    yield vault
    VaultManager.reset_instance()


def test_vt01_key_derivation_deterministic(tmp_path):
    """Fixed passphrase and salt produce a consistent 32-byte key."""
    salt_file = tmp_path / "salt_det"
    key_file = tmp_path / "key_det"

    v1 = VaultManager()
    v1.initialize(passphrase="Secret123", salt_path=salt_file, master_key_file=key_file, iterations=10_000)

    v2 = VaultManager()
    v2.initialize(passphrase="Secret123", salt_path=salt_file, master_key_file=key_file, iterations=10_000)

    # Both instances encrypt and decrypt each other's data
    ct = v1.encrypt("SharedSecretValue")
    assert v2.decrypt(ct) == "SharedSecretValue"


def test_vt02_roundtrip_encryption():
    """Verify standard plaintext roundtrip."""
    plain = "SuperAdminPassword#2026!"
    token = encrypt_secret(plain)
    assert token != plain
    assert len(token) > 28
    decrypted = decrypt_secret(token)
    assert decrypted == plain


def test_vt03_unicode_international():
    """Verify handling of multi-byte UTF-8 international text and emojis."""
    plain = "Mật khẩu bảo mật camera 🎥 🇨🇳 🔒 日本語 test!"
    token = encrypt_secret(plain)
    decrypted = decrypt_secret(token)
    assert decrypted == plain


def test_vt04_empty_and_none_handling():
    """Verify empty string and None return empty string safely."""
    assert encrypt_secret(None) == ""
    assert encrypt_secret("") == ""
    assert decrypt_secret(None) == ""
    assert decrypt_secret("") == ""


def test_vt05_nonce_uniqueness():
    """Ensure 100 consecutive encryptions of identical plaintext produce unique ciphertexts and nonces."""
    plain = "constant_password_value"
    tokens = [encrypt_secret(plain) for _ in range(100)]

    # All tokens must be unique
    assert len(set(tokens)) == 100

    # Extract first 12 bytes (nonce) and assert all are unique
    nonces = [base64.b64decode(t)[:12] for t in tokens]
    assert len(set(nonces)) == 100


def test_vt06_bit_flip_tamper_detection():
    """Altering any bit in the ciphertext payload raises VaultDecryptionError."""
    token = encrypt_secret("ValidPayloadToTamper")
    raw = bytearray(base64.b64decode(token))

    # Flip a bit in the ciphertext section (index 15)
    raw[15] ^= 0x01
    tampered_token = base64.b64encode(raw).decode("utf-8")

    with pytest.raises(VaultDecryptionError):
        decrypt_secret(tampered_token)


def test_vt07_nonce_tamper_detection():
    """Altering 1 byte in the 12-byte nonce triggers VaultDecryptionError."""
    token = encrypt_secret("NonceTamperTest")
    raw = bytearray(base64.b64decode(token))

    # Flip a bit in the nonce section (index 3)
    raw[3] ^= 0x02
    tampered_token = base64.b64encode(raw).decode("utf-8")

    with pytest.raises(VaultDecryptionError):
        decrypt_secret(tampered_token)


def test_vt08_tag_tamper_detection():
    """Altering 1 byte in the trailing 16-byte GHASH tag triggers VaultDecryptionError."""
    token = encrypt_secret("TagTamperTest")
    raw = bytearray(base64.b64decode(token))

    # Flip a bit in the authentication tag (last byte)
    raw[-1] ^= 0xFF
    tampered_token = base64.b64encode(raw).decode("utf-8")

    with pytest.raises(VaultDecryptionError):
        decrypt_secret(tampered_token)


def test_vt09_truncation_attack():
    """Truncating binary payload below minimum length (28 bytes) triggers VaultDecryptionError."""
    # Minimum valid length is 28 bytes (12 nonce + 0 cipher + 16 tag)
    short_raw = b"short_under_28_bytes!"
    assert len(short_raw) < 28
    short_token = base64.b64encode(short_raw).decode("utf-8")

    with pytest.raises(VaultDecryptionError):
        decrypt_secret(short_token)


def test_vt10_malformed_base64():
    """Malformed non-base64 string raises VaultDecryptionError."""
    with pytest.raises(VaultDecryptionError):
        decrypt_secret("!!!not_valid_base64_data???===")


def test_vt11_wrong_master_key(tmp_path):
    """Encrypting with Key A and decrypting with Key B raises VaultDecryptionError."""
    v_a = VaultManager()
    v_a.initialize(passphrase="PassphraseA", salt_path=tmp_path / "salt_a", iterations=5000)

    v_b = VaultManager()
    v_b.initialize(passphrase="PassphraseB", salt_path=tmp_path / "salt_b", iterations=5000)

    token = v_a.encrypt("SecretDataA")
    with pytest.raises(VaultDecryptionError):
        v_b.decrypt(token)


def test_vt12_json_bundle_encryption():
    """Verify dictionary encrypt_json and decrypt_json roundtrip."""
    bundle = {
        "accessToken": "ez_tok_84920491",
        "ssecurity": "sec_hash_9a8b",
        "serviceToken": "svc_tok_1122",
        "expires_in": 3600,
        "is_active": True,
    }
    ct = encrypt_json(bundle)
    decrypted = decrypt_json(ct)
    assert decrypted == bundle

    assert decrypt_json(None) == {}
    assert decrypt_json("") == {}


def test_vt13_secret_masking():
    """Verify mask_secret logic per requirements."""
    # Target requirement: mask_secret('abcdef123456') -> 'abc...456'
    assert mask_secret("abcdef123456") == "abc...456"
    assert mask_secret("admin123") == "adm...123"

    # Short secrets (<= 6 chars)
    assert mask_secret("123456") == "******"
    assert mask_secret("pin") == "***"

    # Empty and None
    assert mask_secret("") == ""
    assert mask_secret(None) == ""


def test_vt14_salt_and_key_file_persistence(tmp_path):
    """Restarting VaultManager with same salt and key file allows seamless decryption."""
    salt_file = tmp_path / "persist_salt"
    key_file = tmp_path / "persist_key"

    v1 = VaultManager()
    v1.initialize(salt_path=salt_file, master_key_file=key_file, iterations=5000)
    token = v1.encrypt("PersistentConfidentialData")

    # Simulate reboot with new instance reading from same files
    v2 = VaultManager()
    v2.initialize(salt_path=salt_file, master_key_file=key_file, iterations=5000)
    assert v2.decrypt(token) == "PersistentConfidentialData"


def test_vt15_invalid_key_length():
    """Directly setting an invalid key length raises VaultConfigurationError."""
    v = VaultManager()
    with pytest.raises(VaultConfigurationError):
        v._set_key(b"too_short_key_16b")
