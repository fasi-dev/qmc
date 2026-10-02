"""Settlement records: AES-256-GCM at rest, HMAC-SHA256 for webhook integrity."""
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def new_storage_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_record(key: bytes, nonce: bytes, record: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, record, None)


def sign_webhook(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()
