"""Session key agreement between payment-api and settlement-worker."""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def new_session_key_exchange():
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def derive_shared(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)
