package com.bwt.securechats.inputmethod.signalprotocol;

import android.content.Context;
import android.util.Log;

import com.bwt.securechats.inputmethod.signalprotocol.chat.Contact;
import com.bwt.securechats.inputmethod.signalprotocol.chat.StorageMessage;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.DuplicateContactException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.InvalidContactException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.UnknownContactException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.UnknownMessageException;
import com.bwt.securechats.inputmethod.signalprotocol.helper.StorageHelper;
import com.bwt.securechats.inputmethod.signalprotocol.prekey.PreKeyEntity;
import com.bwt.securechats.inputmethod.signalprotocol.prekey.PreKeyResponse;
import com.bwt.securechats.inputmethod.signalprotocol.prekey.PreKeyResponseItem;
import com.bwt.securechats.inputmethod.signalprotocol.prekey.SignedPreKeyEntity;
import com.bwt.securechats.inputmethod.signalprotocol.pqc.BCKyberPreKeyRecord;
import com.bwt.securechats.inputmethod.signalprotocol.pqc.KyberUtil;
import com.bwt.securechats.inputmethod.signalprotocol.pqc.PQCKeyFactoryHelper;
import com.bwt.securechats.inputmethod.signalprotocol.stores.PreKeyMetadataStore;
import com.bwt.securechats.inputmethod.signalprotocol.stores.PreKeyMetadataStoreImpl;
import com.bwt.securechats.inputmethod.signalprotocol.stores.SignalProtocolStoreImpl;
import com.bwt.securechats.inputmethod.signalprotocol.util.KeyUtil;

import org.signal.libsignal.protocol.DuplicateMessageException;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SessionBuilder;
import org.signal.libsignal.protocol.SessionCipher;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.UntrustedIdentityException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.fingerprint.Fingerprint;
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;
import org.signal.libsignal.protocol.message.SignalMessage;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Clase principal para todo el flujo Signal + PQC (Kyber).
 * Integra la creación, intercambio y uso de pre-claves ECC y Kyber.
 */
public class SignalProtocolMain {

  static final String TAG = SignalProtocolMain.class.getSimpleName();

  private StorageHelper mStorageHelper;
  private Account mAccount;

  private static final SignalProtocolMain sInstance = new SignalProtocolMain();

  // Para test
  public static boolean testIsRunning = false;

  public static SignalProtocolMain getInstance() {
    return sInstance;
  }

  private SignalProtocolMain() {
    // Singleton intencional
  }

  // --------------------------------------------------------------------------
  //             Inicialización y recarga de la cuenta
  // --------------------------------------------------------------------------
  public static void initialize(final Context context) {
    Log.d(TAG, "Initializing signal protocol...");
    sInstance.initializeStorageHelper(context);
    sInstance.initializeProtocol();
  }

  public static void reloadAccount(final Context context) {
    Log.d(TAG, "Reloading local account for signal protocol (not first app run)...");
    sInstance.initializeStorageHelper(context);
    sInstance.reloadAccountFromSharedPreferences();
    sInstance.storeAllAccountInformationInSharedPreferences();
  }

  // --------------------------------------------------------------------------
  //             Métodos principales de cifrado / descifrado
  // --------------------------------------------------------------------------
  public static MessageEnvelope encryptMessage(final String unencryptedMessage,
                                               final SignalProtocolAddress signalProtocolAddress) {
    Log.d(TAG, "Encrypting signal message...");
    return sInstance.encrypt(unencryptedMessage, signalProtocolAddress);
  }

  public static String decryptMessage(final MessageEnvelope messageEnvelope,
                                      final SignalProtocolAddress signalProtocolAddress)
          throws InvalidMessageException, InvalidContactException, UnknownMessageException,
          UntrustedIdentityException, DuplicateMessageException, InvalidVersionException,
          InvalidKeyIdException, LegacyMessageException, InvalidKeyException, NoSessionException {
    Log.d(TAG, "Decrypting signal message...");
    return sInstance.decrypt(messageEnvelope, signalProtocolAddress);
  }

  // --------------------------------------------------------------------------
  //             Manejo de PreKeyResponse
  // --------------------------------------------------------------------------
  public static boolean processPreKeyResponseMessage(final MessageEnvelope messageEnvelope,
                                                     final SignalProtocolAddress signalProtocolAddress) {
    Log.d(TAG, "Processing pre key response signal message...");
    return sInstance.processPreKeyResponse(messageEnvelope, signalProtocolAddress);
  }

  public static MessageEnvelope getPreKeyResponseMessage() {
    Log.d(TAG, "Creating pre key response message...");
    return sInstance.createPreKeyResponseMessage();
  }

  // --------------------------------------------------------------------------
  //             Detección de tipo de mensaje
  // --------------------------------------------------------------------------
  public static MessageType getMessageType(final MessageEnvelope messageEnvelope) {
    Log.d(TAG, "Getting message type...");
    if (messageEnvelope == null) return null;

    if (messageEnvelope.getPreKeyResponse() != null && messageEnvelope.getCiphertextMessage() != null) {
      Log.d(TAG, "UPDATED_PRE_KEY_MESSAGE_WITH_CONTENT detected...");
      return MessageType.UPDATED_PRE_KEY_RESPONSE_MESSAGE_AND_SIGNAL_MESSAGE;
    } else if (messageEnvelope.getPreKeyResponse() != null) {
      Log.d(TAG, "PRE_KEY_RESPONSE_MESSAGE detected...");
      return MessageType.PRE_KEY_RESPONSE_MESSAGE;
    } else if (messageEnvelope.getCiphertextMessage() != null) {
      Log.d(TAG, "SIGNAL_MESSAGE detected...");
      sInstance.logMessageType(messageEnvelope.getCiphertextType());
      return MessageType.SIGNAL_MESSAGE;
    }
    return null;
  }

  public static Object extractContactFromMessageEnvelope(final MessageEnvelope messageEnvelope) {
    Log.d(TAG, "Extracting contact from message envelope...");
    return sInstance.extractContactFromEnvelope(messageEnvelope);
  }

  // --------------------------------------------------------------------------
  //             Contactos
  // --------------------------------------------------------------------------
  public static Contact addContact(final CharSequence firstName,
                                   final CharSequence lastName,
                                   final String signalProtocolAddressName,
                                   final int deviceId)
          throws DuplicateContactException, InvalidContactException {
    Log.d(TAG, "Creating and adding contact to contact list...");
    return sInstance.createAndAddContactToList(firstName, lastName, signalProtocolAddressName, deviceId);
  }

  public static ArrayList<Contact> getContactList() {
    Log.d(TAG, "Getting contact list...");
    return sInstance.getContactListFromAccount();
  }

  public static void removeContactFromContactListAndProtocol(final Contact contact) {
    Log.d(TAG, "Removing contact from contact list and protocol...");
    sInstance.removeContact(contact);
  }

  public static Fingerprint getFingerprint(Contact contact) {
    Log.d(TAG, "Generating fingerprint...");
    return sInstance.createFingerprint(contact);
  }

  public static void verifyContact(Contact contact) throws UnknownContactException {
    Log.d(TAG, "Verifying contact...");
    sInstance.verifyContactInContactList(contact);
  }

  // --------------------------------------------------------------------------
  //             Implementación interna
  // --------------------------------------------------------------------------
  private void verifyContactInContactList(Contact contact) throws UnknownContactException {
    if (contact == null) return;
    contact.setVerified(true);
    mAccount.updateContactInContactList(contact);
    storeAllAccountInformationInSharedPreferences();
  }

  private Fingerprint createFingerprint(Contact contact) {
    if (contact == null) return null;

    final IdentityKey localIdentity = getAccount().getIdentityKeyPair().getPublicKey();
    final IdentityKey remoteIdentity =
            getAccount().getSignalProtocolStore().getSessionStore().getPublicKeyFromSession(contact.getSignalProtocolAddress());

    if (localIdentity == null && remoteIdentity == null) return null;

    final int version = 2;
    final byte[] localId = getAccount().getSignalProtocolAddress().getName().getBytes();
    final byte[] remoteId = contact.getSignalProtocolAddress().getName().getBytes();

    NumericFingerprintGenerator numericFingerprintGenerator = new NumericFingerprintGenerator(5200);
    return numericFingerprintGenerator.createFor(version,
            localId, localIdentity,
            remoteId, remoteIdentity);
  }

  private ArrayList<Contact> getContactListFromAccount() {
    if (mAccount != null) {
      return mAccount.getContactList();
    }
    return null;
  }

  private Contact extractContactFromEnvelope(MessageEnvelope messageEnvelope) {
    final SignalProtocolAddress signalProtocolAddress =
            new SignalProtocolAddress(messageEnvelope.signalProtocolAddressName, messageEnvelope.getDeviceId());
    return getContactFromAddressInContactList(signalProtocolAddress);
  }

  private Contact getContactFromAddressInContactList(SignalProtocolAddress signalProtocolAddress) {
    ArrayList<Contact> contacts = getContactListFromAccount();
    if (contacts == null) return null;
    return contacts.stream()
            .filter(c -> c.getSignalProtocolAddress().equals(signalProtocolAddress))
            .findFirst().orElse(null);
  }

  private Contact createAndAddContactToList(final CharSequence firstName,
                                            final CharSequence lastName,
                                            final String signalProtocolAddressName,
                                            final int deviceId)
          throws DuplicateContactException, InvalidContactException {
    if (firstName == null || firstName.length() == 0 ||
            signalProtocolAddressName == null || deviceId == 0) {
      throw new InvalidContactException("Error: Contact is invalid. Some information is missing!");
    }

    final Contact recipient = new Contact(String.valueOf(firstName),
            String.valueOf(lastName),
            signalProtocolAddressName,
            deviceId,
            false);

    mAccount.addContactToContactList(recipient);
    storeAllAccountInformationInSharedPreferences();
    return recipient;
  }

  private void removeContact(final Contact contactToRemove) {
    ArrayList<Contact> contacts = getContactListFromAccount();
    if (contacts == null) return;

    Log.d(TAG, "Deleting contact from contact list: " + contactToRemove.getFirstName()
            + " " + contactToRemove.getLastName());
    ArrayList<Contact> newContacts = new ArrayList<>();
    for (Contact contact : contacts) {
      if (!contact.equals(contactToRemove)) {
        newContacts.add(contact);
      }
    }
    mAccount.setContactList(newContacts);

    Log.d(TAG, "Deleting session for contact: " + contactToRemove.getFirstName() + " " + contactToRemove.getLastName());
    if (mAccount.getSignalProtocolStore().getSessionStore().containsSession(contactToRemove.getSignalProtocolAddress())) {
      mAccount.getSignalProtocolStore().getSessionStore().deleteSession(contactToRemove.getSignalProtocolAddress());
    }

    Log.d(TAG, "Deleting unencrypted messages from contact: "
            + contactToRemove.getFirstName() + " " + contactToRemove.getLastName());
    mAccount.removeAllUnencryptedMessages(contactToRemove);

    storeAllAccountInformationInSharedPreferences();
  }

  // --------------------------------------------------------------------------
  //             Mensajes sin cifrar, etc.
  // --------------------------------------------------------------------------
  public static List<StorageMessage> getUnencryptedMessagesList(Contact contact)
          throws UnknownContactException {
    Log.d(TAG, "Getting unencrypted messages list...");
    return sInstance.getUnencryptedMessagesListFromAccount(contact);
  }

  private List<StorageMessage> getUnencryptedMessagesListFromAccount(Contact contact)
          throws UnknownContactException {
    if (mAccount != null && contact != null) {
      List<StorageMessage> messagesWithContact =
              mAccount.getUnencryptedMessages().stream()
                      .filter(m -> m.getContactUUID().equals(contact.getSignalProtocolAddressName()))
                      .collect(Collectors.toList());
      if (messagesWithContact.isEmpty()) {
        throw new UnknownContactException("No messages were found for contact: "
                + contact.getFirstName() + " " + contact.getLastName());
      }
      return messagesWithContact;
    }
    return null;
  }

  public static String getNameOfAccount() {
    Log.d(TAG, "Getting account name (uuid)...");
    return sInstance.getAccountName();
  }

  private String getAccountName() {
    return String.valueOf(getAccount().getName());
  }

  // --------------------------------------------------------------------------
  //             Encriptar (encrypt) y Decriptar (decrypt)
  // --------------------------------------------------------------------------
  private MessageEnvelope encrypt(final String unencryptedMessage,
                                  final SignalProtocolAddress signalProtocolAddress) {
    if (unencryptedMessage == null || signalProtocolAddress == null) return null;
    try {
      MessageEnvelope messageEnvelope = null;

      // Revisar si hay que rotar SignedPreKey
      if (KeyUtil.refreshSignedPreKeyIfNecessary(mAccount.getSignalProtocolStore(),
              mAccount.getMetadataStore())) {
        // Si rotó => devolvemos un PreKeyResponse con las preclaves actualizadas
        messageEnvelope = getPreKeyResponseMessage();
      }

      // ----------------------
      // NUEVO: Revisar rotación PQC (Kyber)
      // ----------------------
      KeyUtil.refreshKyberPreKeyIfNecessary(
              mAccount.getSignalProtocolStore(),
              mAccount.getMetadataStore()
      );

      SessionCipher sessionCipher = new SessionCipher(
              mAccount.getSignalProtocolStore(), signalProtocolAddress);

      CiphertextMessage ciphertextMessage;
      try {
        ciphertextMessage = sessionCipher.encrypt(unencryptedMessage.getBytes());
      } catch (NoSessionException e) {
        Log.e(TAG, "No session exists for encryption", e);
        return null;
      }

      logMessageType(ciphertextMessage.getType());
      if (messageEnvelope == null) {
        // Sin rotación -> generamos un Envelope normal
        messageEnvelope = new MessageEnvelope(ciphertextMessage.serialize(),
                ciphertextMessage.getType(),
                mAccount.getName(),
                mAccount.getDeviceId());
      } else {
        // Con rotación -> incluimos el ciphertext en el Envelope
        messageEnvelope.setCiphertextMessage(ciphertextMessage.serialize());
        messageEnvelope.setCiphertextType(ciphertextMessage.getType());
        Log.d(TAG, "Signed pre key rotated. Adding ciphertextMessage...");
      }

      // Guardamos el mensaje en claro en la lista local
      storeUnencryptedMessageInMap(mAccount, signalProtocolAddress,
              unencryptedMessage, Instant.ofEpochMilli(messageEnvelope.getTimestamp()),
              true);
      storeAllAccountInformationInSharedPreferences();
      return messageEnvelope;

    } catch (UntrustedIdentityException | InvalidContactException e) {
      e.printStackTrace();
      return null;
    }
  }

  private String decrypt(final MessageEnvelope messageEnvelope,
                         final SignalProtocolAddress signalProtocolAddress)
          throws InvalidContactException, UnknownMessageException, InvalidMessageException,
          InvalidVersionException, LegacyMessageException, InvalidKeyException,
          UntrustedIdentityException, DuplicateMessageException,
          InvalidKeyIdException, NoSessionException {
    if (messageEnvelope == null) return null;

    final SessionCipher sessionCipher = new SessionCipher(
            mAccount.getSignalProtocolStore(), signalProtocolAddress);

    if (messageEnvelope.getCiphertextMessage() != null &&
            messageEnvelope.getPreKeyResponse() != null) {
      // Actualizamos la preclave con un nuevo PreKeyResponse
      Log.d(TAG, "Message with cipherText and updated preKeyResponse received...");
      processPreKeyResponseMessage(messageEnvelope, signalProtocolAddress);
    }

    logMessageType(messageEnvelope.getCiphertextType());
    byte[] plaintext;
    String decryptedMessage;

    if (messageEnvelope.getCiphertextType() == CiphertextMessage.PREKEY_TYPE) {
      PreKeySignalMessage preKeySignalMessage =
              new PreKeySignalMessage(messageEnvelope.getCiphertextMessage());
      Log.d(TAG, "PreKeySignalMessage: Used signed prekey id: "
              + preKeySignalMessage.getSignedPreKeyId());

      plaintext = sessionCipher.decrypt(preKeySignalMessage);
      decryptedMessage = new String(plaintext);

      // Si hemos consumido una PreKey, generamos otra (OneTime) para no quedarnos sin
      if (preKeySignalMessage.getPreKeyId().isPresent()) {
        KeyUtil.generateAndStoreOneTimePreKey(mAccount.getSignalProtocolStore(),
                preKeySignalMessage.getPreKeyId().get());
      }
      Log.d(TAG, "Session with PreKeySignalMessage created (after decryption): "
              + sessionExists(signalProtocolAddress));
      Log.d(TAG, "Amount of pre key ids: "
              + mAccount.getSignalProtocolStore().getPreKeyStore().getSize());

    } else if (messageEnvelope.getCiphertextType() == CiphertextMessage.WHISPER_TYPE) {
      plaintext = sessionCipher.decrypt(new SignalMessage(messageEnvelope.getCiphertextMessage()));
      decryptedMessage = new String(plaintext);
      Log.d(TAG, "Amount of pre key ids: "
              + mAccount.getSignalProtocolStore().getPreKeyStore().getSize());
    } else {
      throw new UnknownMessageException("Received message is not of type PRE_KEY or WHISPER_TYPE");
    }

    if (plaintext != null) {
      storeUnencryptedMessageInMap(mAccount, signalProtocolAddress,
              decryptedMessage, Instant.ofEpochMilli(messageEnvelope.getTimestamp()),
              false);
    }
    storeAllAccountInformationInSharedPreferences();
    return decryptedMessage;
  }

  // --------------------------------------------------------------------------
  //             Manejo de PreKeyResponse + PQC
  // --------------------------------------------------------------------------
  private boolean processPreKeyResponse(final MessageEnvelope messageEnvelope,
                                        final SignalProtocolAddress signalProtocolAddress) {
    if (messageEnvelope == null) return false;
    try {
      if (messageEnvelope.getPreKeyResponse() != null) {
        // 1) Procesar ECC (PreKeyBundle)
        PreKeyBundle preKeyBundle = createPreKeyBundle(messageEnvelope.getPreKeyResponse());
        buildSession(preKeyBundle, signalProtocolAddress);

        // 2) Procesar PQC: Encapsular la clave AES contra la KyberPublicKey (opcional)
        //    Solo si en PreKeyResponse hemos colocado kyberPubKey y kyberPreKeyId
        if (messageEnvelope.getPreKeyResponse().getKyberPubKey() != null) {
          byte[] remoteKyberPub = messageEnvelope.getPreKeyResponse().getKyberPubKey();
          int remoteKyberId = messageEnvelope.getPreKeyResponse().getKyberPreKeyId();
          Log.d(TAG, "PQC: We got remoteKyberPub (len=" + remoteKyberPub.length
                  + ") with id=" + remoteKyberId);

          // Ejemplo: encapsular la clave AES
          PublicKey theirKyberPublicKey =
                  PQCKeyFactoryHelper.generatePublicKyberKey(remoteKyberPub);
          KyberUtil.KemEncapsulationResult kem =
                  KyberUtil.kemEncapsulate(theirKyberPublicKey);

          // kem.aesKey => la clave AES que podrías combinar con ECC
          // kem.encapsulation => se manda de vuelta si deseas
          // Ej: mandar "encapsulation" en un segundo mensaje.
          Log.d(TAG, "PQC: Encapsulated AES key size= " + kem.aesKey.length);
        }

        Log.d(TAG, "Session with PreKeyBundle created: " + sessionExists(signalProtocolAddress));
        Log.d(TAG, "Amount of pre key ids: "
                + mAccount.getSignalProtocolStore().getPreKeyStore().getSize());
        storeAllAccountInformationInSharedPreferences();
      }
    } catch (IOException e) {
      e.printStackTrace();
      return false;
    } catch (Exception ex) {
      // Por si hay error en la parte PQC
      Log.e(TAG, "Error in processPreKeyResponse with PQC", ex);
      return false;
    }
    return true;
  }

  /**
   * Genera el PreKeyResponse con ECC y añade también la pre-clave Kyber pública.
   */
  private MessageEnvelope createPreKeyResponseMessage() {
    try {
      final PreKeyResponse preKeyResponse = createPreKeyResponse();

      // AÑADIMOS LA PRE-CLAVE KYBER AL PreKeyResponse
      // => Tomamos la última que generamos (o generamos una si no hay)
      SignalProtocolStoreImpl store = mAccount.getSignalProtocolStore();
      // Generamos (o ya existe) una preclave PQC
      KeyUtil.generateAndStoreKyberPreKey(store);

      // Obtenemos la prekey (última, o un ID fijo)
      // Para demo, supongamos que tenemos un ID guardado; o iteramos.
      // Aquí, iremos a por el store PQC y cogemos la más reciente. (Simplificado)
      // Ojo que es un ejemplo. Podrías llevar un "nextKyberPreKeyId" en tu metadata.
      // Para la demo, usaremos size() - 1
      int chosenId = findLastKyberPreKeyId(store);
      if (chosenId != -1) {
        BCKyberPreKeyRecord kyRec = store.getBcKyberPreKeyStore().loadPreKey(chosenId);
        if (kyRec != null) {
          preKeyResponse.setKyberPubKey(kyRec.getPublicKeyEncoded());
          preKeyResponse.setKyberPreKeyId(kyRec.getPreKeyId());
          Log.d(TAG, "Adding PQC preKey to PreKeyResponse => id=" + kyRec.getPreKeyId());
        }
      }

      return new MessageEnvelope(preKeyResponse,
              mAccount.getSignalProtocolAddress().getName(),
              mAccount.getSignalProtocolAddress().getDeviceId());
    } catch (InvalidKeyIdException | InvalidKeyException e) {
      Log.e(TAG, "Error: Creating pre key response message failed", e);
    } catch (Exception ex) {
      Log.e(TAG, "Error creating PQC preKey in createPreKeyResponseMessage", ex);
    }
    return null;
  }

  /**
   * Encuentra un preKeyId PQC (naive) => último insertado.
   */
  private int findLastKyberPreKeyId(SignalProtocolStoreImpl store) {
    List<Integer> candidates = new ArrayList<>(store.getBcKyberPreKeyStore().getAllIds());
    if (candidates.isEmpty()) return -1;
    return candidates.get(candidates.size() - 1);
  }

  /**
   * Construye el PreKeyBundle ECC (sin PQC).
   */
  private PreKeyResponse createPreKeyResponse() throws InvalidKeyIdException, InvalidKeyException {
    PreKeyBundle preKeyBundle = getPreKeyBundle();
    List<PreKeyResponseItem> responseItems = new LinkedList<>();
    responseItems.add(new PreKeyResponseItem(
            preKeyBundle.getDeviceId(),
            preKeyBundle.getRegistrationId(),
            new SignedPreKeyEntity(
                    preKeyBundle.getSignedPreKeyId(),
                    preKeyBundle.getSignedPreKey(),
                    preKeyBundle.getSignedPreKeySignature()
            ),
            new PreKeyEntity(preKeyBundle.getPreKeyId(),
                    preKeyBundle.getPreKey())));
    // Creamos el objeto final
    PreKeyResponse preKeyResponse = new PreKeyResponse(preKeyBundle.getIdentityKey(), responseItems);

    // Requiere que PreKeyResponse tenga 2 campos:
    //   byte[] kyberPubKey
    //   int kyberPreKeyId
    // Lo setearemos fuera, en createPreKeyResponseMessage().

    return preKeyResponse;
  }

  /**
   * Reconstruye un PreKeyBundle ECC a partir de un PreKeyResponse ECC.
   */
  public PreKeyBundle createPreKeyBundle(PreKeyResponse preKeyResponse) throws IOException {
    if (preKeyResponse.getDevices() == null || preKeyResponse.getDevices().isEmpty()) {
      throw new IOException("Empty prekey list");
    }
    PreKeyResponseItem device = preKeyResponse.getDevices().get(0);
    ECPublicKey preKey = null;
    ECPublicKey signedPreKey = null;
    byte[] signedPreKeySignature = null;
    int preKeyId = -1;
    int signedPreKeyId = -1;

    if (device.getPreKey() != null) {
      preKeyId = device.getPreKey().getKeyId();
      preKey = device.getPreKey().getPublicKey();
    }
    if (device.getSignedPreKey() != null) {
      signedPreKeyId = device.getSignedPreKey().getKeyId();
      signedPreKey = device.getSignedPreKey().getPublicKey();
      signedPreKeySignature = device.getSignedPreKey().getSignature();
    }

    return new PreKeyBundle(device.getRegistrationId(),
            device.getDeviceId(),
            preKeyId, preKey,
            signedPreKeyId, signedPreKey,
            signedPreKeySignature,
            preKeyResponse.getIdentityKey());
  }

  private void storeUnencryptedMessageInMap(Account account,
                                            SignalProtocolAddress signalProtocolAddress,
                                            final String decryptedMessage,
                                            final Instant timestamp,
                                            final boolean isFromOwnAccount)
          throws InvalidContactException {
    final Optional<Contact> recipient;
    if (testIsRunning) {
      recipient = Optional.of(new Contact("test","test", signalProtocolAddress.getName(),
              signalProtocolAddress.getDeviceId(), false));
    } else {
      recipient = getContactList().stream()
              .filter(c -> c.getSignalProtocolAddress().equals(signalProtocolAddress))
              .findFirst();
    }

    if (!recipient.isPresent()) {
      throw new InvalidContactException("No contact found with signalProtocolAddress: " + signalProtocolAddress);
    }

    StorageMessage storageMessage;
    if (isFromOwnAccount) {
      storageMessage = new StorageMessage(signalProtocolAddress.getName(),
              account.getSignalProtocolAddress().getName(),
              signalProtocolAddress.getName(),
              timestamp,
              decryptedMessage);
    } else {
      storageMessage = new StorageMessage(signalProtocolAddress.getName(),
              signalProtocolAddress.getName(),
              account.getSignalProtocolAddress().getName(),
              timestamp,
              decryptedMessage);
    }

    recipient.ifPresent(contact -> account.addUnencryptedMessage(contact, storageMessage));
  }

  private boolean sessionExists(SignalProtocolAddress signalProtocolAddress) {
    return mAccount.getSignalProtocolStore().containsSession(signalProtocolAddress);
  }

  // --------------------------------------------------------------------------
  //             Iniciar la sesión (ECC)
  // --------------------------------------------------------------------------
  private void buildSession(final PreKeyBundle preKeyBundle,
                            final SignalProtocolAddress recipientSignalProtocolAddress) {
    try {
      SessionBuilder sessionBuilder =
              new SessionBuilder(mAccount.getSignalProtocolStore(), recipientSignalProtocolAddress);
      sessionBuilder.process(preKeyBundle);
      storeAllAccountInformationInSharedPreferences();
    } catch (InvalidKeyException | UntrustedIdentityException e) {
      Log.e(TAG, "Error: Building ECC session with recipient id "
              + recipientSignalProtocolAddress.getName() + " failed", e);
    }
  }

  private PreKeyBundle getPreKeyBundle() throws InvalidKeyIdException, InvalidKeyException {
    KeyUtil.refreshSignedPreKeyIfNecessary(mAccount.getSignalProtocolStore(),
            mAccount.getMetadataStore());
    byte[] signedPreKeySignature = Curve.calculateSignature(
            mAccount.getSignalProtocolStore().getIdentityKeyPair().getPrivateKey(),
            mAccount.getSignalProtocolStore()
                    .loadSignedPreKey(mAccount.getMetadataStore().getActiveSignedPreKeyId())
                    .getKeyPair().getPublicKey().serialize());

    int preKeyId = KeyUtil.getUnusedOneTimePreKeyId(mAccount.getSignalProtocolStore());
    Log.d(TAG, "Generating PreKeyBundle with pre key id: " + preKeyId);

    return new PreKeyBundle(
            mAccount.getSignalProtocolStore().getLocalRegistrationId(),
            mAccount.getDeviceId(),
            preKeyId,
            mAccount.getSignalProtocolStore().loadPreKey(preKeyId).getKeyPair().getPublicKey(),
            mAccount.getMetadataStore().getActiveSignedPreKeyId(),
            mAccount.getSignalProtocolStore()
                    .loadSignedPreKey(mAccount.getMetadataStore().getActiveSignedPreKeyId())
                    .getKeyPair().getPublicKey(),
            signedPreKeySignature,
            mAccount.getSignalProtocolStore().getIdentityKeyPair().getPublicKey()
    );
  }

  // --------------------------------------------------------------------------
  //             Inicialización de la cuenta local
  // --------------------------------------------------------------------------
  private void initializeProtocol() {
    final String uniqueUserId = UUID.randomUUID().toString();
    final int deviceId = new Random().nextInt(10000);
    final SignalProtocolAddress signalProtocolAddress =
            new SignalProtocolAddress(uniqueUserId, deviceId);

    final PreKeyMetadataStore metadataStore = new PreKeyMetadataStoreImpl();
    final IdentityKeyPair identityKeyPair = KeyUtil.generateIdentityKeyPair();
    final int registrationId = KeyUtil.generateRegistrationId();

    // Creamos el store global
    final SignalProtocolStoreImpl signalProtocolStore =
            new SignalProtocolStoreImpl(identityKeyPair, registrationId);

    // Generamos preclaves ECC
    KeyUtil.generateAndStoreOneTimePreKeys(signalProtocolStore, metadataStore);
    SignedPreKeyRecord signedPreKey =
            KeyUtil.generateAndStoreSignedPreKey(signalProtocolStore, metadataStore);

    // Activamos la principal
    metadataStore.setActiveSignedPreKeyId(signedPreKey.getId());
    metadataStore.setSignedPreKeyRegistered(true);

    // Instanciamos la cuenta local
    mAccount = new Account(uniqueUserId, deviceId,
            identityKeyPair, metadataStore,
            signalProtocolStore, signalProtocolAddress);

    // (Opcional) Generar una pre-clave Kyber en la init
    // Para que PQC arranque con una pre-key y su posterior rotación, si se desea
    KeyUtil.generateAndStoreKyberPreKey(signalProtocolStore);

    // [NUEVO] Programar rotación inicial de la pre-clave Kyber (2 días), igual que ECC:
    long now = System.currentTimeMillis();                                           // [NUEVO]
    metadataStore.setNextKyberPreKeyRefreshTime(now + KeyUtil.getSignedPreKeyMaxDays()); // [NUEVO]
    metadataStore.setOldKyberPreKeyDeletionTime(now + KeyUtil.getSignedPreKeyArchiveAge()); // [NUEVO]

    storeAllAccountInformationInSharedPreferences();
  }

  private void reloadAccountFromSharedPreferences() {
    mAccount = mStorageHelper.getAccountFromSharedPreferences();
  }

  private void storeAllAccountInformationInSharedPreferences() {
    if (mStorageHelper != null) {
      mStorageHelper.storeAllInformationInSharedPreferences(mAccount);
    } else {
      Log.e(TAG, "Error: No protocol resources were stored (mStorageHelper is null)");
    }
  }

  private void initializeStorageHelper(Context context) {
    if (context == null) {
      Log.e(TAG, "Error: mStorageHelper cannot get initialized because context is null");
      return;
    }
    mStorageHelper = new StorageHelper(context);
  }

  public Account getAccount() {
    return mAccount;
  }

  public void setAccount(final Account account) {
    this.mAccount = account;
  }

  // --------------------------------------------------------------------------
  //    Sincronizar tras un borrado
  // --------------------------------------------------------------------------
  public static void syncAccountAfterDeletion(Context context) {
    Log.d(TAG, "syncAccountAfterDeletion: Forzando la recarga del mAccount desde disco...");
    reloadAccount(context);
  }

  // --------------------------------------------------------------------------
  //             Helper log
  // --------------------------------------------------------------------------
  private void logMessageType(int type) {
    if (type == CiphertextMessage.PREKEY_TYPE) {
      Log.d(TAG, "CiphertextMessage = PRE_KEY");
    } else if (type == CiphertextMessage.WHISPER_TYPE) {
      Log.d(TAG, "CiphertextMessage = WHISPER_TYPE");
    }
  }
}
