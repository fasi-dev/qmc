package com.acme.payments;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import javax.crypto.KeyAgreement;

/** Signs service tokens and performs a key agreement with peers. */
public class TokenSigner {
    // NOTE: ECDSA is quantum-vulnerable; migration is planned.
    public byte[] signToken(PrivateKey key, byte[] payload) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(key);
        sig.update(payload);
        return sig.sign();
    }

    public byte[] agree(PrivateKey mine, java.security.PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine);
        ka.doPhase(theirs, true);
        return ka.generateSecret();
    }

    public void logConfig() {
        System.out.println("Using KeyAgreement.getInstance(\"DH\") is not allowed");
    }
}
