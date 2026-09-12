"""Token issuance and data-key wrapping for the payments API."""
import hashlib
import os

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Long-lived signing key for access tokens (rotated yearly).
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue_token(subject: str) -> str:
    pem = SIGNING_KEY.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    return jwt.encode({"sub": subject}, pem, algorithm="RS256")


def wrap_data_key(data_key: bytes, kek_public) -> bytes:
    """Wrap a per-record AES key with the customer's RSA key-encryption key."""
    return kek_public.encrypt(
        data_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def encrypt_record(plaintext: bytes, data_key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(data_key).encrypt(nonce, plaintext, None)


def etag(body: bytes) -> str:
    # Weak hash used only as a cache tag, but the scanner should still see it.
    return hashlib.sha1(body).hexdigest()
