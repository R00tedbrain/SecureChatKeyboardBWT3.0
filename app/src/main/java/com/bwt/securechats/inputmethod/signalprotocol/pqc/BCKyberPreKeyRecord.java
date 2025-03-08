package com.bwt.securechats.inputmethod.signalprotocol.pqc;

import java.io.Serializable;

/**
 * Almacena la clave pública y privada de Kyber (codificadas),
 * junto con un ID y un flag "used" para indicar si se usó.
 *
 * Se utiliza en BCKyberPreKeyStoreImpl.
 */
public class BCKyberPreKeyRecord implements Serializable {

    private final int preKeyId;
    private final byte[] publicKeyEncoded;   // X.509
    private final byte[] privateKeyEncoded;  // PKCS8
    private boolean used;

    public BCKyberPreKeyRecord(int preKeyId, byte[] pubEnc, byte[] privEnc) {
        this.preKeyId = preKeyId;
        this.publicKeyEncoded = pubEnc;
        this.privateKeyEncoded = privEnc;
        this.used = false;
    }

    public int getPreKeyId() {
        return preKeyId;
    }

    public byte[] getPublicKeyEncoded() {
        return publicKeyEncoded;
    }

    public byte[] getPrivateKeyEncoded() {
        return privateKeyEncoded;
    }

    public boolean isUsed() {
        return used;
    }

    public void markUsed() {
        this.used = true;
    }
}
