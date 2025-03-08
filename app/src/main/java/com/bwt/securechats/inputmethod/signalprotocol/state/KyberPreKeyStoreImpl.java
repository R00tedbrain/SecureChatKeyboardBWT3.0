package com.bwt.securechats.inputmethod.signalprotocol.state;

import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementación de KyberPreKeyStore que guarda los registros Kyber en memoria,
 * en un Map<Integer, byte[]>.
 */
public class KyberPreKeyStoreImpl implements KyberPreKeyStore {

    // En lugar de almacenar objetos KyberPreKeyRecord directamente,
    // guardamos su forma serializada en un array de bytes.
    private final Map<Integer, byte[]> store = new HashMap<>();

    @Override
    public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
        if (!store.containsKey(kyberPreKeyId)) {
            throw new InvalidKeyIdException("No existe KyberPreKeyRecord con id: " + kyberPreKeyId);
        }
        try {
            // Recreamos la instancia a partir de los bytes serializados
            return new KyberPreKeyRecord(store.get(kyberPreKeyId));
        } catch (InvalidMessageException e) {
            // Si la data está corrupta, lanzamos excepción
            throw new AssertionError("Error deserializando KyberPreKeyRecord", e);
        }
    }

    @Override
    public List<KyberPreKeyRecord> loadKyberPreKeys() {
        List<KyberPreKeyRecord> result = new ArrayList<>();
        for (byte[] serialized : store.values()) {
            try {
                result.add(new KyberPreKeyRecord(serialized));
            } catch (InvalidMessageException e) {
                throw new AssertionError("Error deserializando un KyberPreKeyRecord", e);
            }
        }
        return result;
    }

    @Override
    public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) {
        // Se serializa el registro y se almacena en el Map
        store.put(kyberPreKeyId, record.serialize());
    }

    @Override
    public boolean containsKyberPreKey(int kyberPreKeyId) {
        return store.containsKey(kyberPreKeyId);
    }

    @Override
    public void markKyberPreKeyUsed(int kyberPreKeyId) {
        // La clase KyberPreKeyRecord oficial no ofrece un método "markUsed".
        // Si lo necesitas, podrías eliminarlo del store o mantener un flag externo.
        // Por ahora, se deja en blanco:
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
