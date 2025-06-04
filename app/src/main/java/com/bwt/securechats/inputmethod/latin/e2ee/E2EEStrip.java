package com.bwt.securechats.inputmethod.latin.e2ee;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.util.Log;
import android.widget.Toast;

import com.bwt.securechats.inputmethod.latin.e2ee.util.HTMLHelper;
import com.bwt.securechats.inputmethod.signalprotocol.MessageEnvelope;
import com.bwt.securechats.inputmethod.signalprotocol.MessageType;
import com.bwt.securechats.inputmethod.signalprotocol.SignalProtocolMain;
import com.bwt.securechats.inputmethod.signalprotocol.chat.Contact;
import com.bwt.securechats.inputmethod.signalprotocol.chat.StorageMessage;
import com.bwt.securechats.inputmethod.signalprotocol.encoding.EncodeHelper;
import com.bwt.securechats.inputmethod.signalprotocol.encoding.Encoder;
import com.bwt.securechats.inputmethod.signalprotocol.encoding.FairyTaleEncoder;
import com.bwt.securechats.inputmethod.signalprotocol.encoding.RawEncoder;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.DuplicateContactException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.InvalidContactException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.TooManyCharsException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.UnknownContactException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.UnknownMessageException;
import com.bwt.securechats.inputmethod.signalprotocol.util.JsonUtil;

import org.signal.libsignal.protocol.DuplicateMessageException;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.UntrustedIdentityException;
import org.signal.libsignal.protocol.fingerprint.Fingerprint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class E2EEStrip {
  private static final String TAG = E2EEStrip.class.getSimpleName();

  private final Context mContext;

  private final String INFO_CONTACT_ALREADY_EXISTS = "Contact already exists and was not saved";
  private final String INFO_CONTACT_INVALID = "Contact is invalid and was not saved";
  private final String INFO_SESSION_CREATION_FAILED = "Session creation failed. If possible delete sender in contact list and ask for a new keybundle";

  private final int CHAR_THRESHOLD_RAW = 10000;
  private final int CHAR_THRESHOLD_FAIRYTALE = 10000;

  public E2EEStrip(Context context) {
    mContext = context;
  }

  CharSequence encryptMessage(final String unencryptedMessage, final SignalProtocolAddress signalProtocolAddress, Encoder encoder) throws IOException {
    checkMessageLengthForEncodingMethod(unencryptedMessage, encoder, false);
    final MessageEnvelope messageEnvelope = SignalProtocolMain.encryptMessage(unencryptedMessage, signalProtocolAddress);
    String json = JsonUtil.toJson(messageEnvelope);
    if (json == null) return null;
    return encode(json, encoder);
  }

  CharSequence decryptMessage(final MessageEnvelope messageEnvelope, final Contact sender) {
    CharSequence decryptedMessage = null;
    try {
      updateSessionWithNewSignedPreKeyIfNecessary(messageEnvelope, sender);

      decryptedMessage = SignalProtocolMain.decryptMessage(messageEnvelope, sender.getSignalProtocolAddress());
    } catch (InvalidMessageException | NoSessionException | InvalidContactException |
             UnknownMessageException |
             UntrustedIdentityException | DuplicateMessageException | InvalidVersionException |
             InvalidKeyIdException |
             LegacyMessageException | InvalidKeyException e) {
      Log.e(TAG, "Error: Decrypting message failed");
      e.printStackTrace();
    }
    return decryptedMessage;
  }

  public String encode(final String message, final Encoder encoder) throws IOException {
    String encodedMessage = null;
    if (encoder.equals(Encoder.FAIRYTALE))
      encodedMessage = FairyTaleEncoder.encode(message, mContext);
    if (encoder.equals(Encoder.RAW)) encodedMessage = RawEncoder.encode(message);
    return encodedMessage;
  }

  private void updateSessionWithNewSignedPreKeyIfNecessary(MessageEnvelope messageEnvelope, Contact sender) {
    if (messageEnvelope.getPreKeyResponse() != null && messageEnvelope.getCiphertextMessage() != null) {
      SignalProtocolMain.processPreKeyResponseMessage(messageEnvelope, sender.getSignalProtocolAddress());
    }
  }

  CharSequence getEncryptedMessageFromClipboard() {
    ClipboardManager clipboardManager =
        (ClipboardManager) mContext.getSystemService(Context.CLIPBOARD_SERVICE);

    if (clipboardManager != null) {
      try {
        // hint: listener for HTML text needed for using app with telegram
        if (clipboardManager.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN) ||
            clipboardManager.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_HTML)) {
          ClipData.Item item = clipboardManager.getPrimaryClip().getItemAt(0);
          return HTMLHelper.replaceHtmlCharacters(item.getText().toString());
        }
      } catch (Exception e) {
        e.printStackTrace();
        Log.e(TAG, "Error: Getting clipboard message!");
      }
    }
    return null;
  }

  void clearClipboard() {
    ClipboardManager clipboardManager =
        (ClipboardManager) mContext.getSystemService(Context.CLIPBOARD_SERVICE);

    if (clipboardManager != null) {
      try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          clipboardManager.clearPrimaryClip();
          // debug Toast.makeText(mContext, "Clipboard deleted!", Toast.LENGTH_SHORT).show();
        } else {
          // support for older devices
          ClipData clipData = ClipData.newPlainText("", "");
          clipboardManager.setPrimaryClip(clipData);
          // debug Toast.makeText(mContext, "Clipboard deleted!", Toast.LENGTH_SHORT).show();
        }
      } catch (Exception e) {
        e.printStackTrace();
        Log.e(TAG, "Error: Clearing clipboard message!");
      }
    }
  }

  public ArrayList<Contact> getContacts() {
    return SignalProtocolMain.getContactList();
  }

  public Contact createAndAddContactToContacts(final CharSequence firstName, final CharSequence lastName, final String signalProtocolAddressName, final int deviceId) {
    Contact contact = null;
    try {
      contact = SignalProtocolMain.addContact(firstName, lastName, signalProtocolAddressName, deviceId);
    } catch (DuplicateContactException e) {
      Toast.makeText(mContext, INFO_CONTACT_ALREADY_EXISTS, Toast.LENGTH_SHORT).show();
      e.printStackTrace();
    } catch (InvalidContactException e) {
      Toast.makeText(mContext, INFO_CONTACT_INVALID, Toast.LENGTH_SHORT).show();
      e.printStackTrace();
    }
    return contact;
  }

  public boolean createSessionWithContact(Contact chosenContact, MessageEnvelope messageEnvelope, SignalProtocolAddress recipientProtocolAddress) {
    boolean successful = SignalProtocolMain.processPreKeyResponseMessage(messageEnvelope, recipientProtocolAddress);
    if (successful) {
      Toast.makeText(mContext, "Session with " + chosenContact.getFirstName() + " " + chosenContact.getLastName() + " created", Toast.LENGTH_SHORT).show();
    } else {
      Toast.makeText(mContext, INFO_SESSION_CREATION_FAILED, Toast.LENGTH_SHORT).show();
    }
    return successful;
  }

  public String getPreKeyResponseMessage() {
    final MessageEnvelope messageEnvelope = SignalProtocolMain.getPreKeyResponseMessage();
    if (messageEnvelope == null) {
      Log.e(TAG, "Failed to create PreKeyResponseMessage - envelope is null");
      return null;
    }
    String json = JsonUtil.toJson(messageEnvelope);
    if (json == null) {
      Log.e(TAG, "Failed to convert PreKeyResponseMessage to JSON");
    }
    return json;
  }

  public Object getContactFromEnvelope(MessageEnvelope messageEnvelope) {
    return SignalProtocolMain.extractContactFromMessageEnvelope(messageEnvelope);
  }

  public MessageType getMessageType(MessageEnvelope messageEnvelope) {
    return SignalProtocolMain.getMessageType(messageEnvelope);
  }

  public void removeContact(Contact contact) {
    SignalProtocolMain.removeContactFromContactListAndProtocol(contact);
  }

  public List<StorageMessage> getUnencryptedMessages(Contact contact) throws UnknownContactException {
    return SignalProtocolMain.getUnencryptedMessagesList(contact);
  }

  public String getAccountName() {
    return SignalProtocolMain.getNameOfAccount();
  }

  public Fingerprint getFingerprint(Contact contact) {
    return SignalProtocolMain.getFingerprint(contact);
  }

  public void verifyContact(Contact contact) throws UnknownContactException {
    SignalProtocolMain.verifyContact(contact);
  }

  public String decodeMessage(String encodedMessage) throws IOException {
    if (EncodeHelper.encodedTextContainsInvisibleCharacters(encodedMessage)) {
      return FairyTaleEncoder.decode(encodedMessage);
    } else {
      return RawEncoder.decode(encodedMessage);
    }
  }

  public void checkMessageLengthForEncodingMethod(String message, Encoder encodingMethod, boolean isPreKeyResponse) throws TooManyCharsException {
    if (message == null || encodingMethod == null) return;
    
    // Para PreKeyResponse (claves), no aplicamos ninguna limitación
    // ya que las claves Kyber pueden ser muy grandes
    if (isPreKeyResponse) {
      Log.d(TAG, "PreKeyResponse length: " + message.getBytes(StandardCharsets.UTF_8).length + " characters (no limit applied)");
      return; // Sin limitación para claves
    }
    
    final int messageBytes = message.getBytes(StandardCharsets.UTF_8).length;
    if (encodingMethod.equals(Encoder.RAW) && messageBytes > CHAR_THRESHOLD_RAW) {
      throw new TooManyCharsException(String.format("Too many characters for raw message (%s characters, only %s characters allowed)", messageBytes, CHAR_THRESHOLD_RAW));
    } else if (encodingMethod.equals(Encoder.FAIRYTALE) && messageBytes > CHAR_THRESHOLD_FAIRYTALE) {
      throw new TooManyCharsException(String.format("Too many characters for fairytale message (%s characters, only %s characters allowed)", messageBytes, CHAR_THRESHOLD_FAIRYTALE));
    }
  }
}
