"""ML-KEM-768 demonstration via liboqs (already migrated)."""
import oqs

with oqs.KeyEncapsulation("ML-KEM-768") as client:
    public_key = client.generate_keypair()
