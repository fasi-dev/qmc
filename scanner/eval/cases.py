"""Hand-labelled evaluation set for the scanner, written separately from the unit-test corpus (tests/corpus.py).

Labels are GROUND TRUTH (what a careful human reviewer would list), not the scanner's current output. Unit of
labelling, following DECISIONS #29: one finding per cryptographic API usage, identified by (line, algorithm).
Comment/doc mentions are excluded from scoring (they are never executable evidence).

`kind`:
  realistic   - code shaped like real applications
  negative    - looks like crypto but is not executable crypto usage (expected: no findings)
  limitation  - real crypto usage that a lexical/AST scanner without dataflow is known to struggle with.
                Kept in the set on purpose so recall is not overstated.
"""

PYC = "cryptography.hazmat.primitives"

CASES: list[dict] = [
    # ------------------------------------------------------------------ Python, realistic
    dict(id="py-flask-jwt-rs256", kind="realistic", file="app/auth/tokens.py", src=(
        "import jwt\n"
        "from datetime import datetime, timedelta\n"
        "\n"
        "def issue(user_id, private_key):\n"
        "    payload = {'sub': user_id, 'exp': datetime.utcnow() + timedelta(hours=1)}\n"
        "    return jwt.encode(payload, private_key, algorithm='RS256')\n"
        "\n"
        "def check(token, public_key):\n"
        "    return jwt.decode(token, public_key, algorithms=['RS256'])\n"),
        expected=[(6, "RSA"), (9, "RSA")]),
    dict(id="py-envelope-encryption", kind="realistic", file="svc/storage/envelope.py", src=(
        f"from {PYC}.asymmetric import rsa, padding\n"
        f"from {PYC} import hashes\n"
        f"from {PYC}.ciphers.aead import AESGCM\n"
        "\n"
        "def wrap(data: bytes, pub):\n"
        "    dek = AESGCM.generate_key(bit_length=256)\n"
        "    ct = AESGCM(dek).encrypt(nonce, data, None)\n"
        "    wrapped = pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))\n"
        "    return wrapped, ct\n"),
        expected=[(6, "AES"), (7, "AES"), (8, "RSA"), (8, "SHA-256")]),
    dict(id="py-ecdh-x25519-session", kind="realistic", file="net/handshake.py", src=(
        f"from {PYC}.asymmetric.x25519 import X25519PrivateKey\n"
        f"from {PYC}.kdf.hkdf import HKDF\n"
        f"from {PYC} import hashes\n"
        "priv = X25519PrivateKey.generate()\n"
        "shared = priv.exchange(peer_public)\n"
        "key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'hs').derive(shared)\n"),
        expected=[(4, "ECDH"), (6, "SHA-256")]),
    dict(id="py-legacy-checksums", kind="realistic", file="tools/export.py", src=(
        "import hashlib, hmac\n"
        "def sign_export(secret: bytes, body: bytes) -> str:\n"
        "    etag = hashlib.md5(body).hexdigest()\n"
        "    mac = hmac.new(secret, body, hashlib.sha256).hexdigest()\n"
        "    return etag + mac\n"),
        expected=[(3, "MD5"), (4, "HMAC")]),
    dict(id="py-bom-windows-file", kind="realistic", file="win/keys.py", src=(
        "﻿" + f"from {PYC}.asymmetric import ec\n"
        "key = ec.generate_private_key(ec.SECP384R1())\n"
        "sig = key.sign(msg, ec.ECDSA(hashes.SHA384()))\n"),
        expected=[(2, "ECDSA"), (3, "ECDSA")]),
    # ------------------------------------------------------------------ Java, realistic
    dict(id="java-jwt-signer", kind="realistic", file="src/main/java/com/acme/auth/JwtSigner.java", src=(
        "package com.acme.auth;\n"
        "import java.security.*;\n"
        "public class JwtSigner {\n"
        "  private final KeyPair kp;\n"
        "  public JwtSigner() throws Exception {\n"
        "    KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\");\n"
        "    g.initialize(2048);\n"
        "    kp = g.generateKeyPair();\n"
        "  }\n"
        "  public byte[] sign(byte[] data) throws Exception {\n"
        "    Signature s = Signature.getInstance(\"SHA256withRSA\");\n"
        "    s.initSign(kp.getPrivate());\n"
        "    s.update(data);\n"
        "    return s.sign();\n"
        "  }\n"
        "}\n"),
        expected=[(6, "RSA"), (11, "RSA")]),
    dict(id="java-ecdh-and-aes", kind="realistic", file="src/main/java/com/acme/net/Channel.java", src=(
        "import javax.crypto.*;\n"
        "import java.security.*;\n"
        "class Channel {\n"
        "  byte[] agree(PrivateKey a, PublicKey b) throws Exception {\n"
        "    KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");\n"
        "    ka.init(a); ka.doPhase(b, true);\n"
        "    return ka.generateSecret();\n"
        "  }\n"
        "  Cipher c() throws Exception { return Cipher.getInstance(\"AES/GCM/NoPadding\"); }\n"
        "  MessageDigest d() throws Exception { return MessageDigest.getInstance(\"SHA-1\"); }\n"
        "}\n"),
        expected=[(5, "ECDH"), (9, "AES"), (10, "SHA-1")]),
    # ------------------------------------------------------------------ JS/TS, realistic
    dict(id="ts-node-crypto-service", kind="realistic", file="src/crypto/service.ts", src=(
        "import { createHash, createHmac, generateKeyPairSync, createSign } from 'node:crypto';\n"
        "export const fingerprint = (b: Buffer) => createHash('sha256').update(b).digest('hex');\n"
        "export const mac = (k: string, b: string) => createHmac('sha256', k).update(b).digest();\n"
        "export const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });\n"
        "export const label = (b: Buffer) => `sha=${createHash('sha1').update(b).digest('hex')}`;\n"),
        expected=[(2, "SHA-256"), (3, "HMAC"), (4, "EC"), (5, "SHA-1")]),
    dict(id="js-jose-and-webcrypto", kind="realistic", file="web/auth/session.js", src=(
        "import * as jose from 'jose';\n"
        "const jwt = await new jose.SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(key);\n"
        "const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);\n"),
        expected=[(2, "ECDSA"), (3, "ECDSA")]),
    # ------------------------------------------------------------------ config, realistic
    dict(id="nginx-legacy-tls", kind="realistic", file="deploy/nginx/site.conf", src=(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_protocols TLSv1 TLSv1.2;  # TLSv1.3 later\n"
        "  ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:!aNULL;\n"
        "}\n"),
        expected=[(3, "TLS"), (4, "ECDH"), (4, "RSA")]),
    # ------------------------------------------------------------------ negatives
    dict(id="neg-py-strings-and-docs", kind="negative", file="docs_helpers.py", src=(
        "\"\"\"Usage: key = rsa.generate_private_key(65537, 2048)\"\"\"\n"
        "EXAMPLE = 'hashlib.sha1(data)'\n"
        "# hashlib.md5(x) is not used anymore\n"
        "def rsa_label(): return 'RSA-2048'\n"),
        expected=[]),
    dict(id="neg-py-unimported-names", kind="negative", file="processor/compressor.py", src=(
        "class rsa:\n"
        "    @staticmethod\n"
        "    def generate_private_key(*a): return None\n"
        "rsa.generate_private_key(65537, 2048)\n"
        "def sha256(x): return x\n"
        "sha256(b'')\n"),
        expected=[]),
    dict(id="neg-js-no-crypto-import", kind="negative", file="src/util/hash.js", src=(
        "// our own non-crypto string hash\n"
        "export function createHash(name) { return { name }; }\n"
        "const h = createHash('sha256');\n"),
        expected=[]),
    dict(id="neg-js-template-text", kind="negative", file="src/docs.js", src=(
        "const crypto = require('crypto');\n"
        "const help = `Call crypto.createHash('sha1') to hash ${thing}`;\n"),
        expected=[]),
    dict(id="neg-java-comments-strings", kind="negative", file="src/Help.java", src=(
        "import java.security.*;\n"
        "class Help {\n"
        "  // Signature.getInstance(\"SHA256withRSA\");\n"
        "  String s = \"KeyPairGenerator.getInstance(\\\"RSA\\\")\";\n"
        "  /* Cipher.getInstance(\"RSA/ECB/OAEPPadding\") */\n"
        "}\n"),
        expected=[]),
    dict(id="neg-nginx-disabled-ciphers", kind="negative", file="deploy/nginx/hardened.conf", src=(
        "ssl_protocols TLSv1.3;\n"
        "ssl_ciphers !aNULL:!MD5:!RC4:!3DES;\n"),
        expected=[]),
    # ------------------------------------------------------------------ known limitations (real usage)
    dict(id="lim-py-function-alias", kind="limitation", file="lim/alias.py", src=(
        f"from {PYC}.asymmetric import rsa\n"
        "gen = rsa.generate_private_key\n"
        "key = gen(65537, 2048)\n"),
        expected=[(3, "RSA")]),
    dict(id="lim-py-getattr", kind="limitation", file="lim/dyn.py", src=(
        "import hashlib\n"
        "h = getattr(hashlib, 'sha1')(b'x')\n"),
        expected=[(2, "SHA-1")]),
    dict(id="lim-java-constant-algorithm", kind="limitation", file="lim/Const.java", src=(
        "import java.security.*;\n"
        "class Const {\n"
        "  static final String ALG = \"RSA\";\n"
        "  Object k() throws Exception { return KeyPairGenerator.getInstance(ALG); }\n"
        "}\n"),
        expected=[(4, "RSA")]),
    dict(id="lim-js-config-algorithm", kind="limitation", file="lim/cfg.js", src=(
        "const crypto = require('crypto');\n"
        "const cfg = { hash: 'sha1' };\n"
        "const h = crypto.createHash(cfg.hash);\n"),
        expected=[(3, "SHA-1")]),
    dict(id="lim-py-3des", kind="limitation", file="lim/legacy_cipher.py", src=(
        "from Crypto.Cipher import DES3\n"
        "c = DES3.new(key, DES3.MODE_CBC, iv)\n"),
        expected=[(2, "3DES")]),
    dict(id="lim-java-3des", kind="limitation", file="lim/Legacy.java", src=(
        "import javax.crypto.*;\n"
        "class Legacy { Object c() throws Exception { return Cipher.getInstance(\"DESede/CBC/PKCS5Padding\"); } }\n"),
        expected=[(2, "3DES")]),
]
