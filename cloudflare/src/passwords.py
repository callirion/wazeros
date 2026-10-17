"""PBKDF2-SHA256 with async Web Crypto support for Python Workers.

Synchronous helpers are for CPython provisioning/tests only. API handlers use
async helpers. Runtime failures are propagated; work factor is never lowered.
"""
import hashlib
import hmac
import secrets

ITERATIONS = 600_000


def _parse(encoded):
    algorithm, count, salt_hex, expected_hex = encoded.split("$")
    if algorithm != "pbkdf2_sha256" or count != str(ITERATIONS):
        raise ValueError("Unsupported password format")
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(expected_hex)
    if len(salt) != 16 or len(expected) != 32:
        raise ValueError("Invalid password hash length")
    return salt, expected


def _native(password, salt):
    derive = getattr(hashlib, "pbkdf2_hmac", None)
    if not callable(derive):
        raise RuntimeError("Use async password helpers in Python Workers")
    return derive("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32)


def encode(password):
    salt = secrets.token_bytes(16)
    key = _native(password, salt)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${key.hex()}"


def verify(encoded, password):
    try:
        salt, expected = _parse(encoded)
    except (ValueError, TypeError, AttributeError):
        return False
    return hmac.compare_digest(_native(password, salt), expected)


async def _derive(password, salt):
    # Keep CPython tests/provisioning compatible; no pure-Python crypto fallback.
    if callable(getattr(hashlib, "pbkdf2_hmac", None)):
        return _native(password, salt)

    from js import Object, Uint8Array, crypto
    from pyodide.ffi import to_js

    material = Uint8Array.new(to_js(list(password.encode("utf-8"))))
    salt_buffer = Uint8Array.new(to_js(list(salt)))
    key = await crypto.subtle.importKey(
        "raw", material, "PBKDF2", False, to_js(["deriveBits"])
    )
    params = to_js(
        {"name": "PBKDF2", "salt": salt_buffer,
         "iterations": ITERATIONS, "hash": "SHA-256"},
        dict_converter=Object.fromEntries,
    )
    result = await crypto.subtle.deriveBits(params, key, 256)
    return bytes(Uint8Array.new(result).to_py())


async def encode_async(password):
    salt = secrets.token_bytes(16)
    key = await _derive(password, salt)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${key.hex()}"


async def verify_async(encoded, password):
    try:
        salt, expected = _parse(encoded)
    except (ValueError, TypeError, AttributeError):
        return False
    key = await _derive(password, salt)
    return hmac.compare_digest(key, expected)
