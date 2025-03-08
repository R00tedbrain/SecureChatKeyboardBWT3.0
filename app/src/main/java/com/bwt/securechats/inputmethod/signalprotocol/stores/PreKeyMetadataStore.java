package com.bwt.securechats.inputmethod.signalprotocol.stores;

/**
 * Allows storing various metadata around prekey state.
 */
public abstract class PreKeyMetadataStore {

  // ------------------------------------------------
  // Campos para ECC SignedPreKeys
  // ------------------------------------------------
  int nextSignedPreKeyId = 0;
  int activeSignedPreKeyId = 0;
  boolean isSignedPreKeyRegistered = false;
  int signedPreKeyFailureCount = 0;
  int nextOneTimePreKeyId = 0;

  long nextSignedPreKeyRefreshTime = 0L;
  long oldSignedPreKeyDeletionTime = 0L; // lastSignedPreKeyRotationTime + 48h

  // ------------------------------------------------
  // NUEVOS CAMPOS para rotación de pre-claves Kyber
  // ------------------------------------------------
  long nextKyberPreKeyRefreshTime = 0L;
  long oldKyberPreKeyDeletionTime = 0L;

  // ------------------------------------------------
  // Getters/Setters ECC
  // ------------------------------------------------

  public int getNextSignedPreKeyId() {
    return nextSignedPreKeyId;
  }

  public void setNextSignedPreKeyId(int nextSignedPreKeyId) {
    this.nextSignedPreKeyId = nextSignedPreKeyId;
  }

  public int getActiveSignedPreKeyId() {
    return activeSignedPreKeyId;
  }

  public void setActiveSignedPreKeyId(int activeSignedPreKeyId) {
    this.activeSignedPreKeyId = activeSignedPreKeyId;
  }

  public boolean isSignedPreKeyRegistered() {
    return isSignedPreKeyRegistered;
  }

  public void setSignedPreKeyRegistered(boolean signedPreKeyRegistered) {
    isSignedPreKeyRegistered = signedPreKeyRegistered;
  }

  public int getSignedPreKeyFailureCount() {
    return signedPreKeyFailureCount;
  }

  public void setSignedPreKeyFailureCount(int signedPreKeyFailureCount) {
    this.signedPreKeyFailureCount = signedPreKeyFailureCount;
  }

  public int getNextOneTimePreKeyId() {
    return nextOneTimePreKeyId;
  }

  public void setNextOneTimePreKeyId(int nextOneTimePreKeyId) {
    this.nextOneTimePreKeyId = nextOneTimePreKeyId;
  }

  public long getNextSignedPreKeyRefreshTime() {
    return nextSignedPreKeyRefreshTime;
  }

  public void setNextSignedPreKeyRefreshTime(long nextSignedPreKeyRefreshTime) {
    this.nextSignedPreKeyRefreshTime = nextSignedPreKeyRefreshTime;
  }

  public long getOldSignedPreKeyDeletionTime() {
    return oldSignedPreKeyDeletionTime;
  }

  public void setOldSignedPreKeyDeletionTime(long oldSignedPreKeyDeletionTime) {
    this.oldSignedPreKeyDeletionTime = oldSignedPreKeyDeletionTime;
  }

  // ------------------------------------------------
  // Getters/Setters PQC (Kyber)
  // ------------------------------------------------

  public long getNextKyberPreKeyRefreshTime() {
    return nextKyberPreKeyRefreshTime;
  }

  public void setNextKyberPreKeyRefreshTime(long nextKyberPreKeyRefreshTime) {
    this.nextKyberPreKeyRefreshTime = nextKyberPreKeyRefreshTime;
  }

  public long getOldKyberPreKeyDeletionTime() {
    return oldKyberPreKeyDeletionTime;
  }

  public void setOldKyberPreKeyDeletionTime(long oldKyberPreKeyDeletionTime) {
    this.oldKyberPreKeyDeletionTime = oldKyberPreKeyDeletionTime;
  }
}
