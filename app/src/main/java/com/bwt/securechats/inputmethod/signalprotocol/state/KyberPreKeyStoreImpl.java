package com.bwt.securechats.inputmethod.signalprotocol.state;

import android.util.Log;

import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementación en memoria del KyberPreKeyStore usando libsignal 0.73.2
 */
public class KyberPreKeyStoreImpl implements KyberPreKeyStore {

    private static final String TAG = KyberPreKeyStoreImpl.class.getSimpleName();

    private final Map<Integer, KyberPreKeyRecord> store = new HashMap<>();

    @Override
    public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
        if (!store.containsKey(kyberPreKeyId)) {
            throw new InvalidKeyIdException("No KyberPreKey with id: " + kyberPreKeyId);
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
        // En libsignal, marcar como usado típicamente significa remover la clave
        // para que no se pueda reutilizar
        store.remove(kyberPreKeyId);
    }

    /**
     * Método adicional para eliminar una pre-clave Kyber.
     */
    public void removeKyberPreKey(int kyberPreKeyId) {
        store.remove(kyberPreKeyId);
    }

    /**
     * Si deseas implementar la "pre-clave de último recurso", hazlo aquí.
     * Caso contrario, puedes dejarlo sin implementar.
     */
    public KyberPreKeyRecord loadLastResortKyberPreKey() throws InvalidKeyIdException {
        throw new UnsupportedOperationException("No implementado");
    }

    public void storeLastResortKyberPreKey(KyberPreKeyRecord record) {
        throw new UnsupportedOperationException("No implementado");
    }
}
