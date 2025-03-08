package com.bwt.securechats.inputmethod.signalprotocol.pqc;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Store en memoria para las pre-claves Kyber (PQC).
 * Similar a PreKeyStoreImpl, pero guardando BCKyberPreKeyRecord serializados.
 */
public class BCKyberPreKeyStoreImpl {

    private static final String TAG = "BCKyberPreKeyStoreImpl";

    private final Map<Integer, byte[]> store = new HashMap<>();

    public synchronized void storePreKey(BCKyberPreKeyRecord record) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(record);
            oos.close();

            store.put(record.getPreKeyId(), baos.toByteArray());
            Log.d(TAG, "Stored PQC preKey with id=" + record.getPreKeyId());
        } catch (Exception e) {
            throw new RuntimeException("Error storing PQC preKey", e);
        }
    }

    public synchronized BCKyberPreKeyRecord loadPreKey(int preKeyId) {
        if (!store.containsKey(preKeyId)) {
            return null;
        }
        byte[] serialized = store.get(preKeyId);
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
            ObjectInputStream ois = new ObjectInputStream(bais);
            BCKyberPreKeyRecord record = (BCKyberPreKeyRecord) ois.readObject();
            ois.close();
            return record;
        } catch (Exception e) {
            throw new RuntimeException("Error loading PQC preKey (id=" + preKeyId + ")", e);
        }
    }

    public synchronized boolean containsPreKey(int preKeyId) {
        return store.containsKey(preKeyId);
    }

    public synchronized void removePreKey(int preKeyId) {
        store.remove(preKeyId);
        Log.d(TAG, "Removed PQC preKey with id=" + preKeyId);
    }

    public synchronized int size() {
        return store.size();
    }

    /**
     * Devuelve un Set con todos los IDs de pre-clave Kyber actualmente almacenados.
     */
    public synchronized Set<Integer> getAllIds() {
        return store.keySet();
    }
}
