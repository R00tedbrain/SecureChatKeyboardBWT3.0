package com.bwt.securechats.inputmethod.signalprotocol.state;

import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementación mínima (stub) de la interfaz KyberPreKeyStore.
 * Almacena los registros KyberPreKey en un Map en memoria.
 */
public class KyberPreKeyStoreImpl implements KyberPreKeyStore {

    private final Map<Integer, KyberPreKeyRecord> store = new HashMap<>();

    @Override
    public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
        if (!store.containsKey(kyberPreKeyId)) {
            throw new InvalidKeyIdException("No existe KyberPreKeyRecord con id: " + kyberPreKeyId);
        }
        return store.get(kyberPreKeyId);
    }

    @Override
    public List<KyberPreKeyRecord> loadKyberPreKeys() {
        return new ArrayList<>(store.values());
    }

    @Override
    public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) {
        store.put(kyberPreKeyId, record);
    }

    @Override
    public boolean containsKyberPreKey(int kyberPreKeyId) {
        return store.containsKey(kyberPreKeyId);
    }

    @Override
    public void markKyberPreKeyUsed(int kyberPreKeyId) {
        // Si hubiera que marcarla como "usada", habría que mantener un flag en KyberPreKeyRecord.
        // En la implementación oficial, no hay un método para ello, así que aquí lo dejamos en blanco.
        // Ejemplo (solo si tuviéramos un .markUsed()):
        // if (store.containsKey(kyberPreKeyId)) {
        //     store.get(kyberPreKeyId).markUsed();
        // }
    }


    public void removeKyberPreKey(int kyberPreKeyId) {
        store.remove(kyberPreKeyId);
    }


    public KyberPreKeyRecord loadLastResortKyberPreKey() throws InvalidKeyIdException {
        throw new UnsupportedOperationException("No implementado");
    }


    public void storeLastResortKyberPreKey(KyberPreKeyRecord record) {
        throw new UnsupportedOperationException("No implementado");
    }
}
