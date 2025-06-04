package com.bwt.securechats.inputmethod.signalprotocol.util;

import android.util.Log;

import com.bwt.securechats.inputmethod.signalprotocol.pqc.BCKyberPreKeyRecord;
import com.bwt.securechats.inputmethod.signalprotocol.pqc.KyberUtil;
import com.bwt.securechats.inputmethod.signalprotocol.stores.PreKeyMetadataStore;
import com.bwt.securechats.inputmethod.signalprotocol.stores.SignalProtocolStoreImpl;

import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.KeyHelper;
import org.signal.libsignal.protocol.util.Medium;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * Clase de utilidades para generar llaves ECC y ahora, también, llaves Kyber (PQC).
 * Con rotación automática (mismo approach) para ECC y PQC.
 */
public class KeyUtil {

  static final String TAG = KeyUtil.class.getSimpleName();

  // Para ECC
  public static final int BATCH_SIZE = 2; // 100 in Signal app
  private static final long SIGNED_PRE_KEY_MAX_DAYS = TimeUnit.DAYS.toMillis(2);
  private static final long SIGNED_PRE_KEY_ARCHIVE_AGE = TimeUnit.DAYS.toMillis(2);

  // Podemos usar las mismas 2d/2d para PQC, o personalizar
  private static final long KYBER_PRE_KEY_MAX_DAYS = SIGNED_PRE_KEY_MAX_DAYS;     // 2 días
  private static final long KYBER_PRE_KEY_ARCHIVE_AGE = SIGNED_PRE_KEY_ARCHIVE_AGE; // 2 días

  // --------------------------------------------------------------------------
  // ECC Identity + Registration
  // --------------------------------------------------------------------------
  public static IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();
    return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
            identityKeyPairKeys.getPrivateKey());
  }

  public static int generateRegistrationId() {
    return KeyHelper.generateRegistrationId(false);
  }

  // --------------------------------------------------------------------------
  // ECC One-Time PreKeys
  // --------------------------------------------------------------------------
  public synchronized static List<PreKeyRecord> generateAndStoreOneTimePreKeys(
          final SignalProtocolStoreImpl protocolStore,
          final PreKeyMetadataStore metadataStore) {
    Log.d(TAG, "Generating one-time prekeys (ECC)...");
    List<PreKeyRecord> records = new LinkedList<>();
    int preKeyIdOffset = metadataStore.getNextOneTimePreKeyId();

    for (int i = 0; i < BATCH_SIZE; i++) {
      int preKeyId = (preKeyIdOffset + i) % Medium.MAX_VALUE;
      PreKeyRecord record = generateAndStoreOneTimePreKey(protocolStore, preKeyId);
      records.add(record);
    }
    return records;
  }

  public synchronized static PreKeyRecord generateAndStoreOneTimePreKey(
          final SignalProtocolStoreImpl protocolStore,
          final int preKeyId
  ) {
    Log.d(TAG, "Generating one-time prekey (ECC) with id: " + preKeyId);
    ECKeyPair keyPair = Curve.generateKeyPair();
    PreKeyRecord record = new PreKeyRecord(preKeyId, keyPair);
    protocolStore.storePreKey(preKeyId, record);
    return record;
  }

  // --------------------------------------------------------------------------
  // ECC Signed PreKeys
  // --------------------------------------------------------------------------
  public synchronized static SignedPreKeyRecord generateAndStoreSignedPreKey(
          final SignalProtocolStoreImpl protocolStore,
          final PreKeyMetadataStore metadataStore
  ) {
    return generateAndStoreSignedPreKey(protocolStore, metadataStore,
            protocolStore.getIdentityKeyPair().getPrivateKey());
  }

  public synchronized static SignedPreKeyRecord generateAndStoreSignedPreKey(
          final SignalProtocolStoreImpl protocolStore,
          final PreKeyMetadataStore metadataStore,
          final ECPrivateKey privateKey
  ) {
    Log.d(TAG, "Generating signed prekeys (ECC)...");

    int signedPreKeyId = metadataStore.getNextSignedPreKeyId();
    SignedPreKeyRecord record = generateSignedPreKey(signedPreKeyId, privateKey, metadataStore);

    protocolStore.storeSignedPreKey(signedPreKeyId, record);
    metadataStore.setNextSignedPreKeyId((signedPreKeyId + 1) % Medium.MAX_VALUE);
    metadataStore.setNextSignedPreKeyRefreshTime(
            System.currentTimeMillis() + SIGNED_PRE_KEY_MAX_DAYS);
    metadataStore.setOldSignedPreKeyDeletionTime(
            System.currentTimeMillis() + SIGNED_PRE_KEY_ARCHIVE_AGE);

    return record;
  }

  public synchronized static SignedPreKeyRecord generateSignedPreKey(
          final int signedPreKeyId,
          final ECPrivateKey privateKey,
          final PreKeyMetadataStore metadataStore
  ) {
    try {
      ECKeyPair keyPair = Curve.generateKeyPair();
      byte[] signature = Curve.calculateSignature(privateKey, keyPair.getPublicKey().serialize());
      return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  private static void rotateSignedPreKey(SignalProtocolStoreImpl protocolStore,
                                         PreKeyMetadataStore metadataStore) {
    SignedPreKeyRecord signedPreKeyRecord =
            generateAndStoreSignedPreKey(protocolStore, metadataStore);
    metadataStore.setActiveSignedPreKeyId(signedPreKeyRecord.getId());
    metadataStore.setSignedPreKeyRegistered(true);
    metadataStore.setSignedPreKeyFailureCount(0);
  }

  public static Integer getUnusedOneTimePreKeyId(final SignalProtocolStoreImpl protocolStore) {
    if (protocolStore == null || protocolStore.getPreKeyStore() == null) return null;

    final int preKeyId = 1;
    final Boolean preKeyIsUsed = protocolStore.getPreKeyStore().checkPreKeyAvailable(preKeyId);
    if (preKeyIsUsed == null || preKeyIsUsed) {
      Log.d(TAG, "No unused ECC prekey left. Generating new one time prekey with id " + preKeyId);
      generateAndStoreOneTimePreKey(protocolStore, preKeyId);
    } else {
      Log.d(TAG, "ECC Prekey with id " + preKeyId + " is unused");
    }
    return preKeyId;
  }

  public static boolean refreshSignedPreKeyIfNecessary(
          final SignalProtocolStoreImpl protocolStore,
          final PreKeyMetadataStore metadataStore
  ) {
    if (protocolStore == null || metadataStore == null) return false;

    long now = System.currentTimeMillis();
    if (now > metadataStore.getNextSignedPreKeyRefreshTime()) {
      Log.d(TAG, "Rotating signed prekey (ECC)...");
      rotateSignedPreKey(protocolStore, metadataStore);
      return true;
    } else {
      Log.d(TAG, "Rotation of signed prekey not necessary (ECC)...");
    }
    deleteOlderSignedPreKeysIfNecessary(protocolStore, metadataStore);
    return false;
  }

  private static void deleteOlderSignedPreKeysIfNecessary(
          final SignalProtocolStoreImpl protocolStore,
          final PreKeyMetadataStore metadataStore
  ) {
    if (protocolStore == null || metadataStore == null) return;

    long now = System.currentTimeMillis();
    if (now > metadataStore.getOldSignedPreKeyDeletionTime()) {
      Log.d(TAG, "Deleting old signed prekeys (ECC)...");
      protocolStore.getSignedPreKeyStore().removeOldSignedPreKeys(
              metadataStore.getActiveSignedPreKeyId());
    } else {
      Log.d(TAG, "Deletion of old signed prekeys not necessary (ECC)...");
    }
  }

  // --------------------------------------------------------------------------
  //            NUEVO: PreClave Kyber PQC + Rotación
  // --------------------------------------------------------------------------

  /**
   * Genera un ID único para una nueva clave Kyber.
   */
  public static int generateKyberPreKeyId(final SignalProtocolStoreImpl protocolStore) {
    // Usar un ID aleatorio para evitar colisiones, similar a como libsignal maneja otros IDs
    Random random = new SecureRandom();
    int kyberPreKeyId;
    
    // Asegurar que el ID no esté ya en uso
    do {
      kyberPreKeyId = Math.abs(random.nextInt()) % Medium.MAX_VALUE;
    } while (protocolStore.containsKyberPreKey(kyberPreKeyId));
    
    Log.d(TAG, "Generated Kyber prekey ID: " + kyberPreKeyId);
    return kyberPreKeyId;
  }

  /**
   * Genera y almacena una pre-clave Kyber en el store.
   * NOTA: Esta es una implementación temporal que usa BCKyberPreKeyRecord
   * ya que KyberPreKeyRecord real no es accesible desde Java en libsignal 0.73.2
   */
  public static void generateAndStoreKyberPreKey(SignalProtocolStoreImpl store) {
    Log.d(TAG, "Generating & storing a Kyber PreKey...");
    if (store == null) {
      Log.e(TAG, "Store is null => cannot create Kyber prekey!");
      return;
    }
    try {
      // Usamos un ID aleatorio para la clave Kyber
      int kyberPreKeyId = generateKyberPreKeyId(store);
      
      // Generamos el par de claves usando BCKyberPreKeyRecord
      KeyPair kp = KyberUtil.generateKyberKeyPair();
      byte[] pubEnc = kp.getPublic().getEncoded();
      byte[] privEnc = kp.getPrivate().getEncoded();
      
      // Crear el BCKyberPreKeyRecord
      BCKyberPreKeyRecord record = new BCKyberPreKeyRecord(kyberPreKeyId, pubEnc, privEnc);
      
      // Guardar en el store BC
      store.getBcKyberPreKeyStore().storePreKey(record);
      
      Log.d(TAG, "Kyber PreKey stored => id=" + kyberPreKeyId);
      
    } catch (Exception e) {
      Log.e(TAG, "Error generating/storing Kyber preKey", e);
    }
  }

  /**
   * Verifica si es hora de rotar la pre-clave Kyber, con la misma lógica (2 días).
   */
  public static boolean refreshKyberPreKeyIfNecessary(
          final SignalProtocolStoreImpl store,
          final PreKeyMetadataStore metadataStore
  ) {
    if (store == null || metadataStore == null) return false;

    long now = System.currentTimeMillis();
    if (now > metadataStore.getNextKyberPreKeyRefreshTime()) {
      Log.d(TAG, "Rotating Kyber preKey (PQC)...");
      // Generar la nueva
      generateAndStoreKyberPreKey(store);

      // Programar la siguiente rotación en 2 días
      metadataStore.setNextKyberPreKeyRefreshTime(now + KYBER_PRE_KEY_MAX_DAYS);

      // Programar la eliminación de la anterior en 2 días
      metadataStore.setOldKyberPreKeyDeletionTime(now + KYBER_PRE_KEY_ARCHIVE_AGE);
      return true;
    } else {
      Log.d(TAG, "Rotation of Kyber preKey not necessary (PQC)...");
    }

    deleteOldKyberPreKeysIfNecessary(store, metadataStore);
    return false;
  }

  /**
   * Elimina las pre-claves Kyber antiguas si ya cumplió su tiempo.
   */
  private static void deleteOldKyberPreKeysIfNecessary(
          final SignalProtocolStoreImpl store,
          final PreKeyMetadataStore metadataStore
  ) {
    if (store == null || metadataStore == null) return;

    long now = System.currentTimeMillis();
    if (now > metadataStore.getOldKyberPreKeyDeletionTime()) {
      Log.d(TAG, "Deleting old Kyber prekeys (PQC)...");
      List<Integer> allIds = new ArrayList<>(store.getBcKyberPreKeyStore().getAllIds());
      if (allIds.size() > 1) {
        // El criterio: nos quedamos con el ID más alto => la preclave más reciente
        int maxId = Collections.max(allIds);
        for (Integer id : allIds) {
          if (!id.equals(maxId)) {
            store.getBcKyberPreKeyStore().removePreKey(id);
            Log.d(TAG, "Removed old Kyber preKey => id=" + id);
          }
        }
        Log.d(TAG, "Kept only the newest Kyber prekey => id=" + maxId);
      }
    } else {
      Log.d(TAG, "Deletion of old Kyber prekeys not necessary (PQC)...");
    }
  }

  // --------------------------------------------------------------------------
  //   MÉTODOS EXTRA: getSignedPreKeyMaxDays() y getSignedPreKeyArchiveAge()
  //   Para que SignalProtocolMain pueda usarlos sin error
  // --------------------------------------------------------------------------
  public static long getSignedPreKeyMaxDays() {
    return SIGNED_PRE_KEY_MAX_DAYS;
  }

  public static long getSignedPreKeyArchiveAge() {
    return SIGNED_PRE_KEY_ARCHIVE_AGE;
  }
}
