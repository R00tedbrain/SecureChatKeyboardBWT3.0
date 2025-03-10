package com.bwt.securechats.inputmethod.signalprotocol.pqc;

import android.util.Log;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Almacén en memoria para las pre-claves Kyber (PQC).
 * Ahora serializable por Jackson para poder persistirlo en EncryptedSharedPreferences.
 */
@JsonAutoDetect(fieldVisibility = Visibility.ANY)       // Jackson serializa/deserializa campos privados
@JsonIgnoreProperties(ignoreUnknown = true)             // Ignora campos desconocidos en el JSON
public class BCKyberPreKeyStoreImpl implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final String TAG = "BCKyberPreKeyStoreImpl";

    // Mapa con preclaves PQC; Jackson convertirá byte[] a base64
    private final Map<Integer, byte[]> store = new HashMap<>();

    // Constructor por defecto para Jackson
    public BCKyberPreKeyStoreImpl() {
        // Empty for Jackson
    }

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

    // Ignoramos esta propiedad para evitar el error Jackson al deserializar un Set inmutable.
    @JsonIgnore
    public synchronized java.util.Set<Integer> getAllIds() {
        return store.keySet();
    }

    // [Opcional] Getter si lo necesitas
    public Map<Integer, byte[]> getStore() {
        return store;
    }
}
