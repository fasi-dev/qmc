"""Authentication helpers for the (fictional) payment API."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def make_service_keypair():
    # service identity key (RSA-2048)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_token(payload: bytes):
    """Sign a JWT payload with ECDSA P-256."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return private_key.public_key(), signature
