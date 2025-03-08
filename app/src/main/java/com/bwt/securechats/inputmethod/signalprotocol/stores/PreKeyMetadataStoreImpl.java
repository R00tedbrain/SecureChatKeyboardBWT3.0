package com.bwt.securechats.inputmethod.signalprotocol.stores;

/**
 * Implementación concreta de PreKeyMetadataStore.
 * Repite los mismos getters/setters, permitiendo la serialización JSON si usas Jackson.
 */
public class PreKeyMetadataStoreImpl extends PreKeyMetadataStore {

  // ECC
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

  // PQC (Kyber)
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
