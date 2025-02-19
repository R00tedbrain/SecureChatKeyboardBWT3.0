package com.bwt.securechats.inputmethod.signalprotocol.state;



/**
 * Stub minimal de KyberPreKeyRecord.
 * Este stub almacena la representación serializada en bytes y un flag para indicar si se ha usado.
 */
public class KyberPreKeyRecord {
    private final byte[] serializedData;
    private boolean used;

    public KyberPreKeyRecord(byte[] serializedData) {
        this.serializedData = serializedData;
        this.used = false;
    }

    /**
     * Retorna los bytes serializados de esta pre-clave.
     */
    public byte[] serialize() {
        return serializedData;
    }

    /**
     * Indica si esta pre-clave ya ha sido utilizada.
     */
    public boolean isUsed() {
        return used;
    }

    /**
     * Marca esta pre-clave como usada.
     */
    public void markUsed() {
        this.used = true;
    }
}