"""PBKDF2-SHA256 using the cryptography package, not Web Crypto.

Preserves the existing pbkdf2_sha256$600000$salt$hash storage format.
Both synchronous provisioning helpers and asynchronous API helpers are retained.
Cryptographic/backend failures propagate; authentication never fails open.
"""
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000
SALT_BYTES = 16
KEY_BYTES = 32


def _derive(password, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=ITERATIONS,
    ).derive(password.encode("utf-8"))


def _parse(encoded):
    if not isinstance(encoded, str):
        raise ValueError("Invalid password hash")
    algorithm, count, salt_hex, expected_hex = encoded.split("$")
    if algorithm != "pbkdf2_sha256" or count != str(ITERATIONS):
        raise ValueError("Unsupported password format")
    if len(salt_hex) != SALT_BYTES * 2 or len(expected_hex) != KEY_BYTES * 2:
        raise ValueError("Invalid password hash length")
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(expected_hex)
    if len(salt) != SALT_BYTES or len(expected) != KEY_BYTES:
        raise ValueError("Invalid password hash length")
    return salt, expected


def encode(password):
    salt = secrets.token_bytes(SALT_BYTES)
    key = _derive(password, salt)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${key.hex()}"


def verify(encoded, password):
    try:
        salt, expected = _parse(encoded)
    except (ValueError, TypeError):
        return False
    key = _derive(password, salt)
    return hmac.compare_digest(key, expected)


async def encode_async(password):
    return encode(password)


async def verify_async(encoded, password):
    return verify(encoded, password)
