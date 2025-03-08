package com.bwt.securechats.inputmethod.signalprotocol.pqc;

import android.util.Log;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyGenerator;

/**
 * Utilidades para Kyber en Bouncy Castle 1.72:
 * - Generar par de claves (KeyPairGenerator "KYBER")
 * - Encapsular (KEMGenerateSpec)
 * - Decapsular (KEMExtractSpec)
 */
public final class KyberUtil {

    private static final String TAG = "KyberUtil";

    private KyberUtil() {}

    /**
     * Genera un par de claves Kyber con KyberParameterSpec.kyber512 (o 768/1024).
     */
    public static KeyPair generateKyberKeyPair() {
        try {
            if (Security.getProvider("BCPQC") == null) {
                Security.addProvider(new org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider());
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC");
            // Usa kyber512 o kyber768, etc.:
            kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            Log.d(TAG, "Generated Kyber key pair (512).");
            return kp;
        } catch (Exception e) {
            throw new RuntimeException("Error generating Kyber keypair", e);
        }
    }

    /**
     * Encapsula una clave simétrica AES usando la KyberPublicKey del receptor.
     * Devuelve un objeto con:
     *   - aesKeyEncoded: los bytes de la clave AES
     *   - encapsulation: el "ciphertext" que se envía al receptor
     */
    public static KemEncapsulationResult kemEncapsulate(PublicKey recipientPublic) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
            // "AES" indica que la clave generada es apta para cifrado simétrico AES
            keyGen.init(new KEMGenerateSpec(recipientPublic, "AES"), new SecureRandom());

            SecretKeyWithEncapsulation encapsulatedKey =
                    (SecretKeyWithEncapsulation) keyGen.generateKey();

            byte[] aesKey = encapsulatedKey.getEncoded();            // Clave AES
            byte[] encapsulation = encapsulatedKey.getEncapsulation(); // Bloque KEM

            return new KemEncapsulationResult(aesKey, encapsulation);
        } catch (Exception e) {
            throw new RuntimeException("Error in kemEncapsulate()", e);
        }
    }

    /**
     * Decapsula la clave simétrica AES usando la KyberPrivateKey y el ciphertext (encapsulation).
     * Devuelve la misma clave AES que en el lado emisor.
     */
    public static byte[] kemDecapsulate(PrivateKey recipientPrivate, byte[] encapsulation) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
            keyGen.init(new KEMExtractSpec(recipientPrivate, encapsulation, "AES"), new SecureRandom());

            SecretKeyWithEncapsulation extractedKey =
                    (SecretKeyWithEncapsulation) keyGen.generateKey();

            byte[] aesKey = extractedKey.getEncoded();
            return aesKey;
        } catch (Exception e) {
            throw new RuntimeException("Error in kemDecapsulate()", e);
        }
    }

    /**
     * Clase auxiliar para encapsular un par (claveAES, ciphertext).
     */
    public static class KemEncapsulationResult {
        public final byte[] aesKey;
        public final byte[] encapsulation;

        public KemEncapsulationResult(byte[] aesKey, byte[] encapsulation) {
            this.aesKey = aesKey;
            this.encapsulation = encapsulation;
        }
    }
}
