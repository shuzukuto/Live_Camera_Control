"""
backend/app/vault.py

AES-256-GCM AEAD Credential Vault.
Provides at-rest encryption, PBKDF2HMAC key derivation, 96-bit random nonces,
tamper detection, and secret masking utilities.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
import secrets
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("nvr.vault")


class VaultError(Exception):
    """Base exception for all Credential Vault operations."""
    pass


class VaultConfigurationError(VaultError):
    """Raised when vault initialization fails due to invalid configuration or files."""
    pass


class VaultDecryptionError(VaultError):
    """Raised when ciphertext decryption fails due to tampering, corruption, or invalid key."""
    pass


class VaultManager:
    """
    Singleton Manager for AES-256-GCM AEAD encryption and decryption.
    Handles PBKDF2HMAC key derivation, salt persistence, and nonce generation.
    """

    _instance: Optional[VaultManager] = None

    def __init__(self, key_bytes: Optional[bytes] = None) -> None:
        self._aesgcm: Optional[AESGCM] = None
        self._initialized: bool = False
        if key_bytes:
            self._set_key(key_bytes)

    @classmethod
    def get_instance(cls) -> VaultManager:
        """Retrieve the global singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for testing)."""
        cls._instance = None

    def is_initialized(self) -> bool:
        """Returns True if the vault has been initialized with a valid key."""
        return self._initialized and self._aesgcm is not None

    def _set_key(self, key_bytes: bytes) -> None:
        if len(key_bytes) != 32:
            raise VaultConfigurationError(
                f"Master key must be exactly 32 bytes (256 bits), got {len(key_bytes)}"
            )
        self._aesgcm = AESGCM(key_bytes)
        self._initialized = True

    @staticmethod
    def _resolve_salt(salt_path: Path) -> bytes:
        """Read persistent 16-byte salt, or generate and securely save a new one."""
        if salt_path.exists():
            salt_data = salt_path.read_bytes()
            if len(salt_data) >= 16:
                return salt_data[:16]
            logger.warning("Existing salt file %s is under 16 bytes. Regenerating.", salt_path)

        # Generate new 16-byte cryptographic salt
        salt = os.urandom(16)
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt_path.write_bytes(salt)

        try:
            # Set restrictive file permissions on POSIX systems
            os.chmod(salt_path, 0o600)
        except (AttributeError, OSError):
            pass

        logger.info("Generated new vault salt at %s", salt_path)
        return salt

    @staticmethod
    def _resolve_master_passphrase(key_file_path: Path) -> str:
        """
        Resolve master passphrase from environment variables, existing key file,
        or auto-generate a secure random 32-byte secret.
        """
        # 1. Check environment variables
        env_key = (
            os.getenv("VAULT_PASSPHRASE")
            or os.getenv("APP_SECRET_KEY")
            or os.getenv("NVR_MASTER_KEY")
        )
        if env_key and env_key.strip():
            return env_key.strip()

        # 2. Check local key file
        if key_file_path.exists():
            saved_key = key_file_path.read_text(encoding="utf-8").strip()
            if saved_key:
                return saved_key

        # 3. Auto-generate a secure random master secret and persist
        generated_key = secrets.token_urlsafe(32)
        key_file_path.parent.mkdir(parents=True, exist_ok=True)
        key_file_path.write_text(generated_key, encoding="utf-8")

        try:
            os.chmod(key_file_path, 0o600)
        except (AttributeError, OSError):
            pass

        logger.info("Initialized auto-generated master vault key at %s", key_file_path)
        return generated_key

    def initialize(
        self,
        passphrase: Optional[str] = None,
        salt_path: Optional[str | Path] = None,
        master_key_file: Optional[str | Path] = None,
        iterations: int = 600_000,
    ) -> None:
        """
        Initialize the Vault with PBKDF2HMAC key derivation.
        """
        base_data_dir = Path("data")
        salt_p = Path(salt_path) if salt_path else base_data_dir / ".vault_salt"
        key_p = Path(master_key_file) if master_key_file else base_data_dir / ".vault_master_key"

        salt = self._resolve_salt(salt_p)
        secret_passphrase = passphrase if passphrase else self._resolve_master_passphrase(key_p)

        # Derive 32-byte (256-bit) key using PBKDF2HMAC-SHA256 with 600,000 iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        derived_key = kdf.derive(secret_passphrase.encode("utf-8"))
        self._set_key(derived_key)
        logger.info("VaultManager successfully initialized with AES-256-GCM (600k PBKDF2 iters).")

    def _ensure_initialized(self) -> None:
        """Self-initialize with default parameters if not explicitly called."""
        if not self._initialized or self._aesgcm is None:
            self.initialize()

    def encrypt(self, plaintext: Optional[str], associated_data: Optional[bytes] = None) -> str:
        """
        Encrypt a plaintext string using AES-256-GCM.
        Generates a fresh 12-byte nonce per operation.
        Returns base64-encoded string: base64(nonce [12B] + ciphertext + tag [16B]).
        """
        if plaintext is None:
            return ""
        if plaintext == "":
            return ""

        self._ensure_initialized()
        assert self._aesgcm is not None

        # Fresh 96-bit (12 bytes) nonce
        nonce = os.urandom(12)
        plaintext_bytes = plaintext.encode("utf-8")

        # AESGCM.encrypt returns ciphertext + 16-byte tag
        ciphertext_and_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
        packed_payload = nonce + ciphertext_and_tag

        return base64.b64encode(packed_payload).decode("utf-8")

    def decrypt(self, ciphertext_b64: Optional[str], associated_data: Optional[bytes] = None) -> str:
        """
        Decrypt a base64-encoded AES-256-GCM ciphertext.
        Verifies GHASH authentication tag and extracts plaintext.
        Raises VaultDecryptionError if data is tampered, corrupted, truncated, or invalid.
        """
        if ciphertext_b64 is None or ciphertext_b64 == "":
            return ""

        self._ensure_initialized()
        assert self._aesgcm is not None

        # Base64 decode
        try:
            raw_payload = base64.b64decode(ciphertext_b64.encode("utf-8"), validate=True)
        except Exception as exc:
            raise VaultDecryptionError(f"Malformed base64 ciphertext: {exc}") from exc

        # Minimum length: 12 (nonce) + 0 (ciphertext) + 16 (tag) = 28 bytes
        if len(raw_payload) < 28:
            raise VaultDecryptionError(
                f"Ciphertext payload length ({len(raw_payload)} bytes) is below minimum (28 bytes)."
            )

        nonce = raw_payload[:12]
        ciphertext_and_tag = raw_payload[12:]

        try:
            decrypted_bytes = self._aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag as exc:
            raise VaultDecryptionError(
                "Decryption failed: cryptographic tag mismatch. Data may be tampered with or key is incorrect."
            ) from exc
        except UnicodeDecodeError as exc:
            raise VaultDecryptionError(f"Decrypted payload is not valid UTF-8: {exc}") from exc
        except Exception as exc:
            raise VaultDecryptionError(f"Unexpected decryption error: {exc}") from exc


# ------------------------------------------------------------------------------
# Module-level Convenience Functions (Standard Interface Contracts)
# ------------------------------------------------------------------------------

def get_vault() -> VaultManager:
    """Retrieve global VaultManager instance."""
    return VaultManager.get_instance()


def init_vault(
    passphrase: Optional[str] = None,
    salt_path: Optional[str | Path] = None,
    master_key_file: Optional[str | Path] = None,
    iterations: int = 600_000,
) -> None:
    """Initialize the global VaultManager singleton."""
    get_vault().initialize(
        passphrase=passphrase,
        salt_path=salt_path,
        master_key_file=master_key_file,
        iterations=iterations,
    )


def is_vault_initialized() -> bool:
    """Check if global VaultManager is initialized."""
    return get_vault().is_initialized()


def encrypt_secret(plaintext: Optional[str], associated_data: Optional[bytes] = None) -> str:
    """
    Encrypt plaintext secret into base64 AES-256-GCM token.
    Safe for SQLite storage.
    """
    return get_vault().encrypt(plaintext, associated_data)


def decrypt_secret(ciphertext_b64: Optional[str], associated_data: Optional[bytes] = None) -> str:
    """
    Decrypt base64 AES-256-GCM token into plaintext string.
    Raises VaultDecryptionError on tamper or failure.
    """
    return get_vault().decrypt(ciphertext_b64, associated_data)


def encrypt_json(data: Dict[str, Any], associated_data: Optional[bytes] = None) -> str:
    """
    Convenience method to securely encrypt a dictionary (e.g. cloud tokens bundle).
    """
    json_str = json.dumps(data, ensure_ascii=False)
    return encrypt_secret(json_str, associated_data)


def decrypt_json(ciphertext_b64: Optional[str], associated_data: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Convenience method to decrypt and parse an encrypted JSON dictionary.
    """
    raw_str = decrypt_secret(ciphertext_b64, associated_data)
    if not raw_str:
        return {}
    try:
        return json.loads(raw_str)
    except Exception as exc:
        raise VaultDecryptionError(f"Failed to parse decrypted JSON payload: {exc}") from exc


def mask_secret(secret: Optional[str], show_prefix: int = 3, show_suffix: int = 3) -> str:
    """
    Mask a sensitive string for logs and UI display without leaking plaintext.
    Example: mask_secret('abcdef123456') -> 'abc...456'
    Example: mask_secret('123456') -> '******'
    """
    if not secret:
        return ""
    if len(secret) <= (show_prefix + show_suffix):
        return "*" * len(secret)
    return f"{secret[:show_prefix]}...{secret[-show_suffix:]}"
