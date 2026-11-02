"""Client-side SCRAM-SHA-256 verifier so plaintext passwords never reach the server."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ITERATIONS = 4096


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def scram_verifier(
    password: str, *, salt: bytes | None = None, iterations: int = ITERATIONS
) -> str:
    salt = salt if salt is not None else secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.digest(salted, b"Client Key", "sha256")
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.digest(salted, b"Server Key", "sha256")
    return f"SCRAM-SHA-256${iterations}:{_b64(salt)}${_b64(stored_key)}:{_b64(server_key)}"
