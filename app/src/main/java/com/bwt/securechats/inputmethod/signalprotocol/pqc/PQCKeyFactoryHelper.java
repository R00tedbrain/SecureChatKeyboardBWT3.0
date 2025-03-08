package com.bwt.securechats.inputmethod.signalprotocol.pqc;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Helper para convertir bytes <-> objetos PublicKey/PrivateKey Kyber.
 */
public final class PQCKeyFactoryHelper {

    static {
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    private PQCKeyFactoryHelper() {}

    public static PublicKey generatePublicKyberKey(byte[] x509Encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("KYBER", "BCPQC");
        return kf.generatePublic(new X509EncodedKeySpec(x509Encoded));
    }

    public static PrivateKey generatePrivateKyberKey(byte[] pkcs8Encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("KYBER", "BCPQC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Encoded));
    }
}
