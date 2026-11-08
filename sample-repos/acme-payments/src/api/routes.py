"""HTTP routes for the (fictional) payment API. No cryptography in this file: it calls the auth and settlement helpers."""
from src.auth import sign_token
from src.payments.settle import encrypt_record


def issue_session(payload: bytes):
    return sign_token(payload)


def store_settlement(key: bytes, nonce: bytes, record: bytes) -> bytes:
    return encrypt_record(key, nonce, record)
