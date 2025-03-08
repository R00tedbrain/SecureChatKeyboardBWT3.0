package com.bwt.securechats.inputmethod.signalprotocol.stores;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

import java.util.List;
import java.util.UUID;

import android.util.Log;

import com.bwt.securechats.inputmethod.signalprotocol.pqc.BCKyberPreKeyRecord;
import com.bwt.securechats.inputmethod.signalprotocol.pqc.BCKyberPreKeyStoreImpl;

/**
 * Implementación principal del SignalProtocolStore que combina:
 * - IdentityKeyStore
 * - PreKeyStore
 * - SignedPreKeyStore
 * - SessionStore
 * - SenderKeyStore
 *
 * Además, hemos añadido un store PQC (BCKyberPreKeyStoreImpl) para las pre-claves Kyber.
 */
public class SignalProtocolStoreImpl implements SignalProtocolStore, KyberPreKeyStore {

  private static final String TAG = SignalProtocolStoreImpl.class.getSimpleName();

  @JsonProperty
  private final PreKeyStoreImpl preKeyStore = new PreKeyStoreImpl();

  @JsonProperty
  private final SessionStoreImpl sessionStore = new SessionStoreImpl();

  @JsonProperty
  private final SignedPreKeyStoreImpl signedPreKeyStore = new SignedPreKeyStoreImpl();

  @JsonProperty
  private final SenderKeyStoreImpl senderKeyStore = new SenderKeyStoreImpl();

  // NUEVO: Store de pre-claves Kyber (PQC) con Bouncy Castle
  @JsonProperty
  private final BCKyberPreKeyStoreImpl bcKyberPreKeyStore = new BCKyberPreKeyStoreImpl();

  @JsonProperty
  private IdentityKeyStoreImpl identityKeyStore;

  // Constructor principal
  public SignalProtocolStoreImpl(IdentityKeyPair identityKeyPair, int registrationId) {
    this.identityKeyStore = new IdentityKeyStoreImpl(identityKeyPair, registrationId);
  }

  // Constructor sin parámetros (p.e. para Jackson)
  public SignalProtocolStoreImpl() {
  }

  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyStore.getIdentityKeyPair();
  }

  public void setIdentityKeyStore(IdentityKeyStoreImpl identityKeyStore) {
    this.identityKeyStore = identityKeyStore;
  }

  @Override
  public int getLocalRegistrationId() {
    return identityKeyStore.getLocalRegistrationId();
  }

  @Override
  public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    return identityKeyStore.saveIdentity(address, identityKey);
  }

  @Override
  public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
    return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
  }

  @Override
  public IdentityKey getIdentity(SignalProtocolAddress address) {
    return identityKeyStore.getIdentity(address);
  }

  @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    return preKeyStore.loadPreKey(preKeyId);
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    preKeyStore.storePreKey(preKeyId, record);
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    return preKeyStore.containsPreKey(preKeyId);
  }

  @Override
  public void removePreKey(int preKeyId) {
    preKeyStore.removePreKey(preKeyId);
  }

  @Override
  public SessionRecord loadSession(SignalProtocolAddress address) {
    return sessionStore.loadSession(address);
  }

  @Override
  public List<SessionRecord> loadExistingSessions(List<SignalProtocolAddress> addresses) throws NoSessionException {
    return sessionStore.loadExistingSessions(addresses);
  }

  @Override
  public List<Integer> getSubDeviceSessions(String name) {
    return sessionStore.getSubDeviceSessions(name);
  }

  @Override
  public void storeSession(SignalProtocolAddress address, SessionRecord record) {
    sessionStore.storeSession(address, record);
  }

  @Override
  public boolean containsSession(SignalProtocolAddress address) {
    return sessionStore.containsSession(address);
  }

  @Override
  public void deleteSession(SignalProtocolAddress address) {
    sessionStore.deleteSession(address);
  }

  @Override
  public void deleteAllSessions(String name) {
    sessionStore.deleteAllSessions(name);
  }

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
  }

  @Override
  public List<SignedPreKeyRecord> loadSignedPreKeys() {
    return signedPreKeyStore.loadSignedPreKeys();
  }

  @Override
  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
    signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
  }

  @Override
  public boolean containsSignedPreKey(int signedPreKeyId) {
    return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
  }

  @Override
  public void removeSignedPreKey(int signedPreKeyId) {
    signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
  }

  @Override
  public void storeSenderKey(SignalProtocolAddress sender, UUID distributionId, SenderKeyRecord record) {
    senderKeyStore.storeSenderKey(sender, distributionId, record);
  }

  @Override
  public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distributionId) {
    return senderKeyStore.loadSenderKey(sender, distributionId);
  }


  // ================================================================
  // Métodos de KyberPreKeyStore: Por ahora "stub" en libsignal,
  // pero nosotros delegamos a bcKyberPreKeyStore.
  // ================================================================
  @Override
  public KyberPreKeyRecord loadKyberPreKey(int preKeyId) throws InvalidKeyIdException {
    Log.d(TAG, "loadKyberPreKey => not implemented in official libsignal, ignoring");
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }

  @Override
  public List<KyberPreKeyRecord> loadKyberPreKeys() {
    Log.d(TAG, "loadKyberPreKeys => not implemented in official libsignal.");
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }

  @Override
  public void storeKyberPreKey(int preKeyId, KyberPreKeyRecord record) {
    Log.d(TAG, "storeKyberPreKey => not implemented in official libsignal.");
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }

  @Override
  public boolean containsKyberPreKey(int preKeyId) {
    Log.d(TAG, "containsKyberPreKey => not implemented in official libsignal.");
    return false;
  }

  public void removeKyberPreKey(int preKeyId) {
    Log.d(TAG, "removeKyberPreKey => not implemented in official libsignal.");
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }

  public void markKyberPreKeyUsed(int preKeyId) {
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }

  public KyberPreKeyRecord loadLastResortKyberPreKey() throws InvalidKeyIdException {
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }

  public void storeLastResortKyberPreKey(KyberPreKeyRecord record) {
    throw new UnsupportedOperationException("Libsignal internal KyberPreKeyRecord not used.");
  }


  // ------------------------------------------------------------------
  // NUESTRO STORE BouncyCastle para PQC:
  // ------------------------------------------------------------------
  public BCKyberPreKeyStoreImpl getBcKyberPreKeyStore() {
    return bcKyberPreKeyStore;
  }

  // ------------------------------------------------------------------
  // Getters del resto de stores:
  // ------------------------------------------------------------------
  public PreKeyStoreImpl getPreKeyStore() {
    return preKeyStore;
  }

  public SessionStoreImpl getSessionStore() {
    return sessionStore;
  }

  public SignedPreKeyStoreImpl getSignedPreKeyStore() {
    return signedPreKeyStore;
  }

  public SenderKeyStoreImpl getSenderKeyStore() {
    return senderKeyStore;
  }

  public IdentityKeyStoreImpl getIdentityKeyStore() {
    return identityKeyStore;
  }
}
