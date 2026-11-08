"""Refund notifications (fictional): reuses the settlement helpers."""
from .settle import sign_webhook


def notify_refund(secret: bytes, body: bytes) -> str:
    return sign_webhook(secret, body)
