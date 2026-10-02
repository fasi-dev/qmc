"""Developer script (unused): generates a throwaway RSA key for local experiments."""
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
