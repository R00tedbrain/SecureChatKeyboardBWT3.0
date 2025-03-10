package com.bwt.securechats.inputmethod.signalprotocol.helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.bwt.securechats.inputmethod.Masterkey;
import com.bwt.securechats.inputmethod.signalprotocol.Account;
import com.bwt.securechats.inputmethod.signalprotocol.ProtocolIdentifier;
import com.bwt.securechats.inputmethod.signalprotocol.chat.Contact;
import com.bwt.securechats.inputmethod.signalprotocol.chat.StorageMessage;
import com.bwt.securechats.inputmethod.signalprotocol.stores.PreKeyMetadataStore;
import com.bwt.securechats.inputmethod.signalprotocol.stores.SignalProtocolStoreImpl;
import com.bwt.securechats.inputmethod.signalprotocol.util.JsonUtil;

import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.SignalProtocolAddress;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

public class StorageHelper {

  static final String TAG = "StorageHelper_DEBUG";

  // << FLAG para alternar entre EncryptedSharedPreferences y SharedPreferences normal >>
  private static final boolean USE_ENCRYPTED = true;

  private final Context mContext;
  private final String mSharedPreferenceName = "protocol";

  public StorageHelper(Context context) {
    this.mContext = context;
  }

  @SuppressWarnings("unchecked")
  public Account getAccountFromSharedPreferences() {
    Log.d(TAG, "getAccountFromSharedPreferences => start");
    final String name = (String) getClassFromSharedPreferences(ProtocolIdentifier.UNIQUE_USER_ID);
    final SignalProtocolStoreImpl signalProtocolStore =
            (SignalProtocolStoreImpl) getClassFromSharedPreferences(ProtocolIdentifier.PROTOCOL_STORE);
    if (signalProtocolStore == null) {
      logError("signalProtocolStore");
      return null;
    }
    final IdentityKeyPair identityKeyPair = signalProtocolStore.getIdentityKeyPair();

    final PreKeyMetadataStore metadataStore =
            (PreKeyMetadataStore) getClassFromSharedPreferences(ProtocolIdentifier.METADATA_STORE);
    final SignalProtocolAddress signalProtocolAddress =
            (SignalProtocolAddress) getClassFromSharedPreferences(ProtocolIdentifier.PROTOCOL_ADDRESS);

    // Recupera la lista de mensajes desencriptados
    final ArrayList<StorageMessage> unencryptedMessages = JsonUtil.convertUnencryptedMessagesList(
            (ArrayList<StorageMessage>) getClassFromSharedPreferences(ProtocolIdentifier.UNENCRYPTED_MESSAGES)
    );

    // Recupera la lista de contactos
    final ArrayList<Contact> contactList = JsonUtil.convertContactsList(
            (ArrayList<Contact>) getClassFromSharedPreferences(ProtocolIdentifier.CONTACTS)
    );

    if (signalProtocolAddress == null) {
      logError("signalProtocolAddress");
      return null;
    }
    Account account = new Account(
            name,
            signalProtocolAddress.getDeviceId(),
            identityKeyPair,
            metadataStore,
            signalProtocolStore,
            signalProtocolAddress
    );

    if (unencryptedMessages != null) {
      account.setUnencryptedMessages(new ArrayList<>(unencryptedMessages));
    }
    if (contactList != null) {
      account.setContactList(new ArrayList<>(contactList));
    }

    Log.d(TAG, "getAccountFromSharedPreferences => done (account != null? " + (account != null) + ")");
    return account;
  }

  public void storeAllInformationInSharedPreferences(final Account account) {
    if (account == null) {
      logError("account");
      return;
    }
    Log.d(TAG, "storeAllInformationInSharedPreferences => storing everything");
    storeMetaDataStoreInSharedPreferences(account.getMetadataStore());
    storeUniqueUserIdInSharedPreferences(account.getName());
    storeSignalProtocolInSharedPreferences(account.getSignalProtocolStore());
    storeSignalProtocolAddressInSharedPreferences(account.getSignalProtocolAddress());
    storeDeviceIdInSharedPreferences(account.getDeviceId());
    storeUnencryptedMessagesListInSharedPreferences(account.getUnencryptedMessages());
    storeContactListInSharedPreferences(account.getContactList());
  }

  private void storeUnencryptedMessagesListInSharedPreferences(List<StorageMessage> unencryptedMessages) {
    Log.d(TAG, "storeUnencryptedMessagesListInSharedPreferences => size="
            + (unencryptedMessages == null ? "null" : unencryptedMessages.size()));
    storeInSharedPreferences(ProtocolIdentifier.UNENCRYPTED_MESSAGES, unencryptedMessages);
  }

  public void storeMetaDataStoreInSharedPreferences(final PreKeyMetadataStore metadataStore) {
    storeInSharedPreferences(ProtocolIdentifier.METADATA_STORE, metadataStore);
  }

  public void storeUniqueUserIdInSharedPreferences(final String uniqueUserId) {
    storeInSharedPreferences(ProtocolIdentifier.UNIQUE_USER_ID, uniqueUserId);
  }

  public void storeSignalProtocolInSharedPreferences(final SignalProtocolStoreImpl signalProtocolStore) {
    storeInSharedPreferences(ProtocolIdentifier.PROTOCOL_STORE, signalProtocolStore);
  }

  public void storeSignalProtocolAddressInSharedPreferences(final SignalProtocolAddress signalProtocolAddress) {
    storeInSharedPreferences(ProtocolIdentifier.PROTOCOL_ADDRESS, signalProtocolAddress);
  }

  public void storeDeviceIdInSharedPreferences(final Integer deviceId) {
    storeInSharedPreferences(ProtocolIdentifier.DEVICE_ID, deviceId);
  }

  private void storeContactListInSharedPreferences(List<Contact> contactList) {
    storeInSharedPreferences(ProtocolIdentifier.CONTACTS, contactList);
  }

  public void storeInSharedPreferences(final ProtocolIdentifier protocolIdentifier, final Object objectToStore) {
    if (mContext == null) {
      logError("mContext");
      return;
    }
    SharedPreferences sharedPreferences = getSafeSharedPreferences();
    if (sharedPreferences == null) {
      logError("sharedPreferences");
      return;
    }

    final String json = JsonUtil.toJson(objectToStore);
    Log.d(TAG, "storeInSharedPreferences => " + protocolIdentifier + ", jsonLength="
            + (json == null ? "null" : json.length()));
    sharedPreferences.edit()
            .putString(String.valueOf(protocolIdentifier), json)
            .apply();
  }

  @SuppressWarnings("unchecked")
  public <T> T getClassFromSharedPreferences(final ProtocolIdentifier protocolIdentifier) {
    if (mContext == null) {
      logError("mContext");
      return null;
    }
    SharedPreferences sharedPreferences = getSafeSharedPreferences();
    if (sharedPreferences == null) {
      logError("sharedPreferences");
      return null;
    }
    final String json = sharedPreferences.getString(String.valueOf(protocolIdentifier), null);
    try {
      if (json == null) {
        throw new IOException("Required content not found! Possibly never stored?");
      }
      return (T) JsonUtil.fromJson(json, protocolIdentifier.className);
    } catch (IOException e) {
      Log.e(TAG, "Error: Could not process " + protocolIdentifier + " from SharedPreferences", e);
    }
    return null;
  }

  private void logError(final String nameObject) {
    Log.e(TAG, "Error: Possible null value for " + nameObject);
  }

  // ------------------------------------------------------------------------
  // NUEVO MÉTODO: Borrar historial de un contacto a partir de su contactUUID
  // ------------------------------------------------------------------------
  public void deleteMessagesForContact(String contactUUID) {
    Log.d(TAG, "deleteMessagesForContact => " + contactUUID);
    if (contactUUID == null || contactUUID.trim().isEmpty()) {
      Log.e(TAG, "deleteMessagesForContact: contactUUID inválido => return");
      return;
    }

    Account account = getAccountFromSharedPreferences();
    if (account == null) {
      Log.e(TAG, "deleteMessagesForContact: Account is null => cannot proceed");
      return;
    }

    List<StorageMessage> allMessages = account.getUnencryptedMessages();
    if (allMessages == null) {
      Log.i(TAG, "deleteMessagesForContact => allMessages is null => nothing to remove");
      return;
    }

    int before = allMessages.size();
    Log.d(TAG, "deleteMessagesForContact => before removal => size=" + before);

    allMessages.removeIf(msg -> {
      boolean match = contactUUID.equals(msg.getContactUUID());
      if (match) {
        Log.d(TAG, "Deleting message => " + msg);
      }
      return match;
    });

    int after = allMessages.size();
    Log.i(TAG, "deleteMessagesForContact => removed " + (before - after)
            + " messages for contactUUID=" + contactUUID);

    account.setUnencryptedMessages(new ArrayList<>(allMessages));
    Log.d(TAG, "deleteMessagesForContact => storing updated account info");
    storeAllInformationInSharedPreferences(account);
  }

  /**
   * Decide si usas EncryptedSharedPreferences o normal, según USE_ENCRYPTED.
   */
  private SharedPreferences getSafeSharedPreferences() {
    if (USE_ENCRYPTED) {
      return getEncryptedPreferences();
    } else {
      return getNormalPreferences();
    }
  }

  /**
   * SharedPreferences normal (no cifradas).
   */
  private SharedPreferences getNormalPreferences() {
    return mContext.getSharedPreferences(mSharedPreferenceName, Context.MODE_PRIVATE);
  }

  /**
   * SharedPreferences cifradas con TU Masterkey.
   */
  private SharedPreferences getEncryptedPreferences() {
    try {
      // Llamas a TU com.bwt.securechats.inputmethod.Masterkey
      MasterKey masterKey = com.bwt.securechats.inputmethod.Masterkey.getMasterKey(mContext);
      if (masterKey == null) {
        Log.e(TAG, "getEncryptedPreferences => MasterKey is null. Returning null.");
        return null;
      }
      return EncryptedSharedPreferences.create(
              mContext,
              mSharedPreferenceName,
              masterKey,
              EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
              EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      );
    } catch (GeneralSecurityException | IOException e) {
      Log.e(TAG, "Error initializing EncryptedSharedPreferences", e);
      return null;
    }
  }
}