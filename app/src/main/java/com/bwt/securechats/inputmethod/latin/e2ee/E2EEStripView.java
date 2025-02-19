package com.bwt.securechats.inputmethod.latin.e2ee;

import android.animation.TypeEvaluator;
import android.animation.ValueAnimator;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.text.Editable;
import android.text.Html;
import android.text.TextWatcher;
import android.text.method.ScrollingMovementMethod;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.TableLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.bwt.securechats.inputmethod.BuildConfig;
import com.bwt.securechats.inputmethod.R;
import com.bwt.securechats.inputmethod.keyboard.MainKeyboardView;
import com.bwt.securechats.inputmethod.latin.RichInputConnection;
import com.bwt.securechats.inputmethod.latin.e2ee.adapter.ListAdapterContacts;
import com.bwt.securechats.inputmethod.latin.e2ee.adapter.ListAdapterMessages;
import com.bwt.securechats.inputmethod.latin.e2ee.util.HTMLHelper;
import com.bwt.securechats.inputmethod.signalprotocol.MessageEnvelope;
import com.bwt.securechats.inputmethod.signalprotocol.MessageType;
import com.bwt.securechats.inputmethod.signalprotocol.chat.Contact;
import com.bwt.securechats.inputmethod.signalprotocol.chat.StorageMessage;
import com.bwt.securechats.inputmethod.signalprotocol.encoding.Encoder;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.TooManyCharsException;
import com.bwt.securechats.inputmethod.signalprotocol.exceptions.UnknownContactException;
import com.bwt.securechats.inputmethod.signalprotocol.helper.StorageHelper;
import com.bwt.securechats.inputmethod.signalprotocol.util.JsonUtil;
import com.bwt.securechats.inputmethod.signalprotocol.SignalProtocolMain; // <-- Asegúrate de tener este import

import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.fingerprint.Fingerprint;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public class E2EEStripView extends RelativeLayout
        implements ListAdapterContacts.ListAdapterContactInterface {

  private static final String TAG = "E2EEStripView_DEBUG";

  MainKeyboardView mMainKeyboardView;
  E2EEStrip mE2EEStrip;
  Listener mListener;

  private E2EEStripVisibilityGroup mE2EEStripVisibilityGroup;
  private ViewGroup mE2EEMainStrip;

  private RichInputConnection mRichInputConnection;

  // main view
  private LinearLayout mLayoutE2EEMainView;
  private ImageButton mEncryptButton;
  private ImageButton mDecryptButton;
  private ImageButton mRecipientButton;
  private ImageButton mChatLogsButton;
  private ImageButton mShowHelpButton;
  private TextView mInfoTextView;
  private EditText mInputEditText;
  private ImageButton mClearUserInputButton;
  private ImageButton mSelectEncodingFairyTaleButton;
  private ImageButton mSelectEncodingRawButton;

  // add contact view
  private LinearLayout mLayoutE2EEAddContactView;
  private TextView mAddContactInfoTextView;
  private EditText mAddContactFirstNameInputEditText;
  private EditText mAddContactLastNameInputEditText;
  private ImageButton mAddContactCancelButton;
  private ImageButton mAddContactAddButton;

  // contact list view
  private LinearLayout mLayoutE2EEContactListView;
  private TextView mContactListInfoTextView;
  private ListView mContactList;
  private ImageButton mContactListReturnButton;
  private ImageButton mContactListInviteButton; // send pre key response message

  // messages view
  private LinearLayout mLayoutE2EEMessagesListView;
  private TextView mMessagesListInfoTextView;
  private ListView mMessagesList;
  private ImageButton mMessagesListReturnButton;
  // Botón para borrar historial
  private ImageButton mMessagesListDeleteHistoryButton;

  // help view
  private LinearLayout mLayoutE2EEHelpView;
  private TextView mHelpInfoTextView;
  private TextView mHelpViewTextView;
  private ImageButton mHelpViewReturnButton;
  private TextView mHelpVersionTextView;

  // verify contact view
  private LinearLayout mLayoutE2EEVerifyContactView;
  private TextView mVerifyContactInfoTextView;
  private TableLayout mVerifyContactTableView;
  private ImageButton mVerifyContactReturnButton;
  private ImageButton mVerifyContactVerifyButton;
  private TextView[] mCodes = new TextView[12];

  private Contact chosenContact;

  private Encoder encodingMethod = Encoder.RAW; // raw is default

  // info texts
  private final String INFO_NO_CONTACT_CHOSEN = "No contact chosen";
  private final String INFO_PRE_KEY_DETECTED = "Keybundle detected: click on decrypt to save the content";
  private final String INFO_SIGNAL_MESSAGE_DETECTED = "Encrypted message detected: click on decrypt to view message";
  private final String INFO_PRE_KEY_AND_SIGNAL_MESSAGE_DETECTED = "Encrypted update message detected: click on decrypt to view message";
  private final String INFO_ADD_CONTACT = "Add contact to send/receive messages";
  private final String INFO_CONTACT_LIST = "Choose your chat partner to send/receive messages. If you want to chat with someone new, invite them via the add button";
  private final String INFO_HELP = "Q&A";
  private final String INFO_MESSAGES_LIST_DEFAULT = "Choose a contact first to see messages here";
  private final String INFO_NO_SAVED_MESSAGES = "There are no saved messages for this contact";
  private final String INFO_VERIFY_CONTACT = "To verify the security of your end-to-end encryption with %s, compare the numbers above with their device";

  private final String INFO_SESSION_CREATION_FAILED = "Session creation failed. If possible delete sender in contact list and ask for a new keybundle";
  private final String INFO_CONTACT_CREATION_FAILED = "Could not create contact. Abort";
  private final String INFO_ADD_FIRSTNAME_ADD_CONTACT = "Enter a first name to create contact";
  private final String INFO_CHOOSE_CONTACT_FIRST = "Please choose a contact first";
  private final String INFO_NO_MESSAGE_TO_ENCRYPT = "No message to encrypt";
  private final String INFO_NO_MESSAGE_TO_DECRYPT = "No message to decrypt";
  private final String INFO_MESSAGE_DECRYPTION_FAILED = "Message could not be decrypted. Possible Reasons: You decrypted a message you already have decrypted once or the session is invalid. In that case delete your contact and tell your contact to delete you and ask for a new invite";
  private final String INFO_CANNOT_DECRYPT_OWN_MESSAGES = "You can't decrypt your own messages";
  private final String INFO_SIGNAL_MESSAGE_NO_CONTACT_FOUND = "Please add the contact first";
  private final String INFO_MESSAGE_ENCRYPTION_FAILED = "Message could not be encrypted";
  private final String INFO_UPDATE_CONTACT_FAILED = "Could not update contact information";

  private static class E2EEStripVisibilityGroup {
    private final View mE2EEStripView;
    private final View mE2EEStrip;

    public E2EEStripVisibilityGroup(final View e2EEStripView, final ViewGroup e2EEStrip) {
      mE2EEStripView = e2EEStripView;
      mE2EEStrip = e2EEStrip;
      showE2EEStrip();
    }

    public void showE2EEStrip() {
      mE2EEStrip.setVisibility(VISIBLE);
    }
  }

  public E2EEStripView(final Context context, final AttributeSet attrs) {
    this(context, attrs, R.attr.e2eeStripViewStyle);
  }

  public E2EEStripView(final Context context, final AttributeSet attrs, final int defStyle) {
    super(context, attrs, defStyle);

    mE2EEStrip = new E2EEStrip(getContext());

    final LayoutInflater inflater = LayoutInflater.from(context);
    inflater.inflate(R.layout.ee2e_main_view, this);

    setupMainView();
    setupAddContactView();
    setupContactListView();
    setupMessagesListView();
    setupHelpView();
    setupVerifyContactView();

    mE2EEStripVisibilityGroup = new E2EEStripVisibilityGroup(this, mE2EEMainStrip);
  }

  // ---------------------------------------------------------
  //  Secciones de configuración de cada vista
  // ---------------------------------------------------------

  private void setupVerifyContactView() {
    mLayoutE2EEVerifyContactView = findViewById(R.id.e2ee_verify_contact_wrapper);
    mVerifyContactInfoTextView = findViewById(R.id.e2ee_verify_contact_info_text);
    mVerifyContactTableView = findViewById(R.id.e2ee_verify_contact_number_table);
    mVerifyContactReturnButton = findViewById(R.id.e2ee_verify_contact_return_button);
    mVerifyContactVerifyButton = findViewById(R.id.e2ee_verify_contact_verify_button);
    mCodes[0] = findViewById(R.id.code_first);
    mCodes[1] = findViewById(R.id.code_second);
    mCodes[2] = findViewById(R.id.code_third);
    mCodes[3] = findViewById(R.id.code_fourth);
    mCodes[4] = findViewById(R.id.code_fifth);
    mCodes[5] = findViewById(R.id.code_sixth);
    mCodes[6] = findViewById(R.id.code_seventh);
    mCodes[7] = findViewById(R.id.code_eighth);
    mCodes[8] = findViewById(R.id.code_ninth);
    mCodes[9] = findViewById(R.id.code_tenth);
    mCodes[10] = findViewById(R.id.code_eleventh);
    mCodes[11] = findViewById(R.id.code_twelth);

    createVerifyContactReturnButtonClickListener();
    createVerifyContactVerifyButtonClickListener();
    loadFingerprintInVerifyContactView();

    if (chosenContact == null) return;
    setInfoTextViewMessage(
            mVerifyContactInfoTextView,
            String.format(INFO_VERIFY_CONTACT, chosenContact.getFirstName() + " " + chosenContact.getLastName())
    );
  }

  private void createVerifyContactVerifyButtonClickListener() {
    if (mVerifyContactVerifyButton == null) return;
    mVerifyContactVerifyButton.setOnClickListener(v -> {
      Log.d(TAG, "verifyContactVerifyButton clicked");
      try {
        mE2EEStrip.verifyContact(chosenContact);
        loadContactsIntoContactsListView();
        showOnlyUIView(UIView.CONTACT_LIST_VIEW);
      } catch (UnknownContactException e) {
        Log.e(TAG, "Error verifying contact", e);
        Toast.makeText(getContext(), INFO_UPDATE_CONTACT_FAILED, Toast.LENGTH_SHORT).show();
      }
    });
  }

  private void loadFingerprintInVerifyContactView() {
    if (chosenContact == null) return;

    createVerifyContactReturnButtonClickListener();
    setInfoTextViewMessage(
            mVerifyContactInfoTextView,
            String.format(INFO_VERIFY_CONTACT, chosenContact.getFirstName() + " " + chosenContact.getLastName())
    );

    final Fingerprint fingerprint = mE2EEStrip.getFingerprint(chosenContact);
    if (fingerprint == null) return;
    setFingerprintViews(fingerprint, true);
  }

  private String[] getSegments(Fingerprint fingerprint, int segmentCount) {
    Log.d(TAG, "getSegments called, segmentCount=" + segmentCount);
    String[] segments = new String[segmentCount];
    String digits = fingerprint.getDisplayableFingerprint().getDisplayText();
    int partSize = digits.length() / segmentCount;

    for (int i = 0; i < segmentCount; i++) {
      segments[i] = digits.substring(i * partSize, (i * partSize) + partSize);
    }
    return segments;
  }

  private void setFingerprintViews(Fingerprint fingerprint, boolean animate) {
    Log.d(TAG, "setFingerprintViews called, animate=" + animate);
    String[] segments = getSegments(fingerprint, mCodes.length);

    for (int i = 0; i < mCodes.length; i++) {
      if (animate) setCodeSegment(mCodes[i], segments[i]);
      else mCodes[i].setText(segments[i]);
    }
  }

  private void setCodeSegment(final TextView codeView, String segment) {
    Log.d(TAG, "setCodeSegment: segment=" + segment);
    ValueAnimator valueAnimator = new ValueAnimator();
    valueAnimator.setObjectValues(0, Integer.parseInt(segment));

    valueAnimator.addUpdateListener(animation -> {
      int value = (int) animation.getAnimatedValue();
      codeView.setText(String.format(Locale.getDefault(), "%05d", value));
    });

    valueAnimator.setEvaluator((TypeEvaluator<Integer>) (fraction, startValue, endValue)
            -> Math.round(startValue + (endValue - startValue) * fraction));

    valueAnimator.setDuration(1000);
    valueAnimator.start();
  }

  private void createVerifyContactReturnButtonClickListener() {
    if (mVerifyContactReturnButton == null) return;
    mVerifyContactReturnButton.setOnClickListener(v -> {
      Log.d(TAG, "verifyContactReturnButton clicked");
      showOnlyUIView(UIView.CONTACT_LIST_VIEW);
    });
  }

  private void setupHelpView() {
    mLayoutE2EEHelpView = findViewById(R.id.e2ee_help_view_wrapper);
    mHelpInfoTextView = findViewById(R.id.e2ee_help_info_text);
    mHelpViewTextView = findViewById(R.id.e2ee_help_view_text);
    mHelpViewReturnButton = findViewById(R.id.e2ee_help_list_return_button);
    mHelpVersionTextView = findViewById(R.id.e2ee_help_view_version_text);

    mHelpViewTextView.setText(
            Html.fromHtml(
                    getResources().getString(R.string.e2ee_help_view_text),
                    Html.FROM_HTML_SEPARATOR_LINE_BREAK_HEADING
            )
    );
    mHelpViewTextView.setMovementMethod(new ScrollingMovementMethod());
    setInfoTextViewMessage(mHelpInfoTextView, INFO_HELP);

    mHelpVersionTextView.setText(String.format("%s%s", "v", BuildConfig.VERSION_NAME));
    createHelpReturnButtonClickListener();
  }

  private void createHelpReturnButtonClickListener() {
    if (mHelpViewReturnButton == null) return;
    mHelpViewReturnButton.setOnClickListener(v -> {
      Log.d(TAG, "helpViewReturnButton clicked");
      showOnlyUIView(UIView.MAIN_VIEW);
    });
  }

  private void setupMessagesListView() {
    mLayoutE2EEMessagesListView = findViewById(R.id.e2ee_messages_list_wrapper);
    mMessagesListInfoTextView = findViewById(R.id.e2ee_messages_list_info_text);
    mMessagesList = findViewById(R.id.e2ee_messages_list);
    mMessagesListReturnButton = findViewById(R.id.e2ee_messages_list_return_button);

    // Botón para borrar historial
    mMessagesListDeleteHistoryButton = findViewById(R.id.e2ee_messages_list_delete_history_button);
    createMessagesListDeleteHistoryButtonClickListener();

    refreshContactInMessageInfoField();
    createMessagesListReturnButtonClickListener();
    loadMessagesIntoMessagesListView();
  }

  /**
   * Escucha del nuevo botón de borrado de historial.
   * Se usa signalProtocolAddressName como "ID" de contacto
   * para borrar de la lista global de StorageMessage.
   */
  private void createMessagesListDeleteHistoryButtonClickListener() {
    if (mMessagesListDeleteHistoryButton == null) return;
    mMessagesListDeleteHistoryButton.setOnClickListener(v -> {
      Log.d(TAG, "DeleteHistoryButton CLICKED");
      if (chosenContact == null) {
        Log.d(TAG, "No contact chosen => can't delete messages");
        Toast.makeText(getContext(), "No contact chosen", Toast.LENGTH_SHORT).show();
        return;
      }
      // El "contactUUID" en StorageMessage se corresponde con chosenContact.getSignalProtocolAddressName()
      String contactUUID = chosenContact.getSignalProtocolAddressName();

      Log.d(TAG, "Proceeding to delete messages for contactUUID=" + contactUUID);
      StorageHelper storageHelper = new StorageHelper(getContext());
      storageHelper.deleteMessagesForContact(contactUUID);

      // >>> AÑADIMOS LA RE-CARGA DEL ACCOUNT EN MEMORIA <<<
      try {
        // Forzamos a SignalProtocolMain a recargar la cuenta desde disco
        SignalProtocolMain.reloadAccount(getContext());
        Log.d(TAG, "SignalProtocolMain.reloadAccount() completed successfully.");
      } catch (Exception ex) {
        Log.e(TAG, "Could not reload account after deletion", ex);
      }
      // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

      // Refrescar la lista en pantalla
      loadMessagesIntoMessagesListView();

      Toast.makeText(
              getContext(),
              "History deleted for contact UUID: " + contactUUID,
              Toast.LENGTH_SHORT
      ).show();
    });
  }

  private void refreshContactInMessageInfoField() {
    if (mMessagesListInfoTextView == null) return;
    if (chosenContact != null) {
      setInfoTextViewMessage(
              mMessagesListInfoTextView,
              "Message log with: " + chosenContact.getFirstName() + " " + chosenContact.getLastName()
      );
    } else {
      setInfoTextViewMessage(mMessagesListInfoTextView, INFO_MESSAGES_LIST_DEFAULT);
    }
  }

  private void loadMessagesIntoMessagesListView() {
    Log.d(TAG, "loadMessagesIntoMessagesListView called");
    List<StorageMessage> messages = null;
    String accountName = null;

    if (chosenContact != null) {
      try {
        Log.d(TAG, "chosenContact=" + chosenContact.getFirstName() + " / " + chosenContact.getLastName());
        messages = mE2EEStrip.getUnencryptedMessages(chosenContact);
        accountName = mE2EEStrip.getAccountName();
      } catch (UnknownContactException e) {
        Log.e(TAG, "UnknownContactException => no saved messages", e);
        Toast.makeText(getContext(), INFO_NO_SAVED_MESSAGES, Toast.LENGTH_SHORT).show();
      }
    } else {
      Log.d(TAG, "chosenContact is null => no messages to load");
    }

    if (messages == null) {
      messages = new ArrayList<>();
    } else {
      messages.sort(Comparator.comparing(StorageMessage::getTimestamp));
    }
    Log.d(TAG, "Messages after sort => size=" + messages.size());

    final ArrayList<Object> messagesAsObjectsList = new ArrayList<>(messages);
    final ListAdapterMessages listAdapterMessages = new ListAdapterMessages(
            this.getContext(),
            R.layout.e2ee_messages_element_view,
            messagesAsObjectsList,
            accountName
    );
    mMessagesList.setAdapter(listAdapterMessages);

    changeHeightOfMessageListView(messages);
  }

  private void changeHeightOfMessageListView(List<StorageMessage> messages) {
    if (messages == null) return;
    Log.d(TAG, "changeHeightOfMessageListView => messages.size=" + messages.size());
    LinearLayout.LayoutParams params;
    if (messages.size() == 0) {
      params = (LinearLayout.LayoutParams) mMessagesList.getLayoutParams();
      params.height = 0;
      mMessagesList.setLayoutParams(params);
    } else {
      params = (LinearLayout.LayoutParams) mMessagesList.getLayoutParams();
      params.height = 700;
      mMessagesList.setLayoutParams(params);
    }
  }

  private void setupContactListView() {
    mLayoutE2EEContactListView = findViewById(R.id.e2ee_contact_list_wrapper);
    mContactListInfoTextView = findViewById(R.id.e2ee_contact_list_info_text);
    mContactList = findViewById(R.id.e2ee_contact_list);
    mContactListReturnButton = findViewById(R.id.e2ee_contact_list_return_button);
    mContactListInviteButton = findViewById(R.id.e2ee_contact_list_invite_new_contact_button);

    createContactListReturnButtonClickListener();
    createContactListInviteButtonClickListener();

    setInfoTextViewMessage(mContactListInfoTextView, INFO_CONTACT_LIST);

    loadContactsIntoContactsListView();
  }

  private void createMessagesListReturnButtonClickListener() {
    if (mMessagesListReturnButton == null) return;
    mMessagesListReturnButton.setOnClickListener(v -> {
      Log.d(TAG, "messagesListReturnButton clicked => showOnlyUIView(MAIN_VIEW)");
      showOnlyUIView(UIView.MAIN_VIEW);
    });
  }

  private void createContactListReturnButtonClickListener() {
    if (mContactListReturnButton == null) return;
    mContactListReturnButton.setOnClickListener(v -> {
      Log.d(TAG, "contactListReturnButton clicked => showOnlyUIView(MAIN_VIEW)");
      showOnlyUIView(UIView.MAIN_VIEW);
    });
  }

  private void createContactListInviteButtonClickListener() {
    if (mContactListInviteButton == null) return;
    mContactListInviteButton.setOnClickListener(v -> {
      Log.d(TAG, "contactListInviteButton clicked => sendPreKeyResponseMessageToApplication");
      showOnlyUIView(UIView.MAIN_VIEW);
      sendPreKeyResponseMessageToApplication();
    });
  }

  private void loadContactsIntoContactsListView() {
    Log.d(TAG, "loadContactsIntoContactsListView called");
    ArrayList<Contact> contacts = mE2EEStrip.getContacts();
    if (contacts == null) {
      Log.d(TAG, "No contacts found (contacts=null)");
      return;
    }
    Log.d(TAG, "contacts.size=" + contacts.size());

    final ArrayList<Object> contactsAsObjectsList = new ArrayList<>(contacts);
    final ListAdapterContacts listAdapterContacts = new ListAdapterContacts(
            this.getContext(),
            R.layout.e2ee_contact_list_element_view,
            contactsAsObjectsList
    );
    listAdapterContacts.setListener(this);
    mContactList.setAdapter(listAdapterContacts);
  }

  private void setupAddContactView() {
    mLayoutE2EEAddContactView = findViewById(R.id.e2ee_add_contact_wrapper);
    mAddContactInfoTextView = findViewById(R.id.e2ee_add_contact_info_text);
    mAddContactFirstNameInputEditText = findViewById(R.id.e2ee_add_contact_first_name_input_field);
    mAddContactLastNameInputEditText = findViewById(R.id.e2ee_add_contact_last_name_input_field);
    mAddContactCancelButton = findViewById(R.id.e2ee_add_contact_cancel_button);
    mAddContactAddButton = findViewById(R.id.e2ee_add_contact_button);

    setupFirstNameInputEditTextField();
    setupLastNameInputEditTextField();

    mAddContactInfoTextView.setText(INFO_ADD_CONTACT);

    createAddContactCancelClickListener();
  }

  private void setupFirstNameInputEditTextField() {
    if (mAddContactFirstNameInputEditText == null) return;
    mAddContactFirstNameInputEditText.setMovementMethod(new ScrollingMovementMethod());
    mAddContactFirstNameInputEditText.setOnFocusChangeListener((v, hasFocus) -> {
      if (hasFocus) {
        Log.d(TAG, "Focus on FIRST NAME field => setOtherIC");
        mRichInputConnection.setOtherIC(mAddContactFirstNameInputEditText);
      }
      mRichInputConnection.setShouldUseOtherIC(hasFocus);
    });
  }

  private void setupLastNameInputEditTextField() {
    if (mAddContactLastNameInputEditText == null) return;
    mAddContactLastNameInputEditText.setMovementMethod(new ScrollingMovementMethod());
    mAddContactLastNameInputEditText.setOnFocusChangeListener((v, hasFocus) -> {
      if (hasFocus) {
        Log.d(TAG, "Focus on LAST NAME field => setOtherIC");
        mRichInputConnection.setOtherIC(mAddContactLastNameInputEditText);
      }
      mRichInputConnection.setShouldUseOtherIC(hasFocus);
    });
  }

  private void createAddContactAddClickListener(final MessageEnvelope messageEnvelope) {
    if (mAddContactAddButton == null) return;
    mAddContactAddButton.setOnClickListener(v -> addContact(messageEnvelope));
  }

  private void addContact(final MessageEnvelope messageEnvelope) {
    Log.d(TAG, "addContact => creating new contact from envelope");
    final CharSequence firstName = mAddContactFirstNameInputEditText.getText();
    final CharSequence lastName = mAddContactLastNameInputEditText.getText();

    final String signalProtocolAddressName = messageEnvelope.getSignalProtocolAddressName();
    final int deviceId = messageEnvelope.getDeviceId();
    final SignalProtocolAddress recipientProtocolAddress =
            new SignalProtocolAddress(signalProtocolAddressName, deviceId);

    if (!providedContactInformationIsValid(firstName, lastName)) return;
    chosenContact = mE2EEStrip.createAndAddContactToContacts(
            firstName, lastName, recipientProtocolAddress.getName(), deviceId
    );

    if (chosenContact == null) {
      abortContactAdding();
      return;
    } else {
      Log.d(TAG, "chosenContact = " + chosenContact);
    }

    resetAddContactInputTextFields();
    showOnlyUIView(UIView.MAIN_VIEW);

    if (messageEnvelope.getPreKeyResponse() != null) {
      Log.d(TAG, "We have a PRE_KEY_RESPONSE => createSessionWithContact");
      final boolean successful = mE2EEStrip.createSessionWithContact(
              chosenContact, messageEnvelope, recipientProtocolAddress);
      if (successful) {
        setInfoTextViewMessage(
                mInfoTextView,
                "Contact " + chosenContact.getFirstName() + " " + chosenContact.getLastName()
                        + " created. You can send messages now"
        );
      } else {
        setInfoTextViewMessage(mInfoTextView, INFO_SESSION_CREATION_FAILED);
      }
    }

    if (messageEnvelope.getCiphertextMessage() != null) {
      Log.d(TAG, "We have a ciphertext => decryptMessageAndShowMessageInMainInputField");
      decryptMessageAndShowMessageInMainInputField(messageEnvelope, chosenContact, false);
      changeImageButtonState(mDecryptButton, ButtonState.DISABLED);
    }
  }

  private void abortContactAdding() {
    Toast.makeText(getContext(), INFO_CONTACT_CREATION_FAILED, Toast.LENGTH_SHORT).show();
    Log.d(TAG, "Contact creation failed => abort");
    showOnlyUIView(UIView.MAIN_VIEW);
    resetChosenContactAndInfoText();
  }

  private void resetAddContactInputTextFields() {
    mAddContactFirstNameInputEditText.setText("");
    mAddContactLastNameInputEditText.setText("");
  }

  private boolean providedContactInformationIsValid(CharSequence firstName, CharSequence lastName) {
    if (firstName == null || firstName.length() == 0) {
      Toast.makeText(getContext(), INFO_ADD_FIRSTNAME_ADD_CONTACT, Toast.LENGTH_SHORT).show();
      return false;
    }
    return true;
  }

  private void createAddContactCancelClickListener() {
    if (mAddContactCancelButton != null) {
      mAddContactCancelButton.setOnClickListener(v -> {
        Log.d(TAG, "addContactCancelButton clicked => MAIN_VIEW");
        showOnlyUIView(UIView.MAIN_VIEW);
        setInfoTextViewMessage(mInfoTextView, INFO_NO_CONTACT_CHOSEN);
        mE2EEStrip.clearClipboard();
      });
    }
  }

  private void changeImageButtonState(ImageButton imageButton, ButtonState state) {
    Log.d(TAG, "changeImageButtonState => " + state);
    if (state.equals(ButtonState.ENABLED)) {
      imageButton.setEnabled(true);
    } else if (state.equals(ButtonState.DISABLED)) {
      imageButton.setEnabled(false);
    }
  }

  private void setupMainView() {
    mLayoutE2EEMainView = findViewById(R.id.e2ee_main_wrapper);
    mE2EEMainStrip = findViewById(R.id.e2ee_main_button_strip);
    mEncryptButton = findViewById(R.id.e2ee_button_encrypt);
    mDecryptButton = findViewById(R.id.e2ee_button_decrypt);
    mRecipientButton = findViewById(R.id.e2ee_button_select_recipient);
    mChatLogsButton = findViewById(R.id.e2ee_button_chat_logs);
    mShowHelpButton = findViewById(R.id.e2ee_button_show_help);
    mInfoTextView = findViewById(R.id.e2ee_info_text);
    mInputEditText = findViewById(R.id.e2ee_input_field);
    mClearUserInputButton = findViewById(R.id.e2ee_button_clear_text);
    mSelectEncodingFairyTaleButton = findViewById(R.id.e2ee_button_select_encoding_fairytale);
    mSelectEncodingRawButton = findViewById(R.id.e2ee_button_select_encoding_raw);

    setMainInfoTextTextChangeListener();
    setMainInfoTextClearChosenContactListener();
    setInfoTextViewMessage(mInfoTextView, INFO_NO_CONTACT_CHOSEN);

    createButtonEncryptClickListener();
    createButtonDecryptClickListener();
    createButtonClearUserInputClickListener();
    createButtonRecipientClickListener();
    createButtonSelectEncryptionMethodClickListener();
    createButtonChatLogsClickListener();
    createButtonShowHelpClickListener();

    setupMessageInputEditTextField();
    initClipboardListenerToChangeStateOfDecryptButton();
  }

  private void setMainInfoTextClearChosenContactListener() {
    if (mInfoTextView == null) return;
    mInfoTextView.setOnClickListener(v -> {
      Log.d(TAG, "InfoTextView clicked => resetChosenContactAndInfoText()");
      resetChosenContactAndInfoText();
    });
  }

  private void initClipboardListenerToChangeStateOfDecryptButton() {
    final ClipboardManager clipboardManager =
            (ClipboardManager) this.getContext().getSystemService(Context.CLIPBOARD_SERVICE);

    clipboardManager.addPrimaryClipChangedListener(() -> {
      Log.d(TAG, "Clipboard changed => check for encrypted data");
      try {
        String item = null;
        boolean isHTML = false;
        if (clipboardManager.getPrimaryClipDescription() != null &&
                (clipboardManager.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)
                        || clipboardManager.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_HTML))) {
          isHTML = clipboardManager.getPrimaryClipDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_HTML);
          item = String.valueOf(clipboardManager.getPrimaryClip().getItemAt(0).getText());
        }

        if (item == null || item.isEmpty()) return;
        if (isHTML) {
          item = HTMLHelper.replaceHtmlCharacters(item);
        }

        final String decodedItem = mE2EEStrip.decodeMessage(item);
        if (decodedItem == null) return;

        final MessageEnvelope envelope = JsonUtil.fromJson(decodedItem, MessageEnvelope.class);
        if (envelope == null) return;

        final MessageType type = mE2EEStrip.getMessageType(envelope);
        if (type == MessageType.UPDATED_PRE_KEY_RESPONSE_MESSAGE_AND_SIGNAL_MESSAGE) {
          changeImageButtonState(mDecryptButton, ButtonState.ENABLED);
          setInfoTextViewMessage(mInfoTextView, INFO_PRE_KEY_AND_SIGNAL_MESSAGE_DETECTED);
        } else if (type == MessageType.PRE_KEY_RESPONSE_MESSAGE) {
          changeImageButtonState(mDecryptButton, ButtonState.ENABLED);
          setInfoTextViewMessage(mInfoTextView, INFO_PRE_KEY_DETECTED);
        } else if (type == MessageType.SIGNAL_MESSAGE) {
          changeImageButtonState(mEncryptButton, ButtonState.ENABLED);
          setInfoTextViewMessage(mInfoTextView, INFO_SIGNAL_MESSAGE_DETECTED);
        }
      } catch (IOException e) {
        Log.e(TAG, "Error reading from clipboard", e);
      }
    });
  }

  private void setMainInfoTextTextChangeListener() {
    if (mInfoTextView == null) return;
    mInfoTextView.addTextChangedListener(new TextWatcher() {
      @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
      @Override public void onTextChanged(CharSequence s, int start, int before, int count) { }
      @Override public void afterTextChanged(Editable s) {
        if (s.toString().equals(INFO_NO_CONTACT_CHOSEN)) {
          Log.d(TAG, "InfoText => NO_CONTACT_CHOSEN => disabling encrypt/decrypt");
          changeImageButtonState(mDecryptButton, ButtonState.DISABLED);
          changeImageButtonState(mEncryptButton, ButtonState.DISABLED);
        } else {
          Log.d(TAG, "InfoText changed => enabling encrypt/decrypt");
          changeImageButtonState(mDecryptButton, ButtonState.ENABLED);
          changeImageButtonState(mEncryptButton, ButtonState.ENABLED);
        }
      }
    });
  }

  private void setInfoTextViewMessage(final TextView textView, final String message) {
    Log.d(TAG, "setInfoTextViewMessage => " + message);
    if (textView == null) return;
    textView.setText(message);
  }

  private void createButtonEncryptClickListener() {
    if (mEncryptButton == null) return;
    mEncryptButton.setOnClickListener(v -> {
      Log.d(TAG, "EncryptButton clicked => encryptAndSendInputFieldContent()");
      encryptAndSendInputFieldContent();
    });
  }

  private void encryptAndSendInputFieldContent() {
    if (chosenContact == null) {
      Log.d(TAG, "No contact chosen => cannot encrypt");
      Toast.makeText(getContext(), INFO_CHOOSE_CONTACT_FIRST, Toast.LENGTH_SHORT).show();
      return;
    }

    if (mInputEditText != null && mInputEditText.getText().length() > 0) {
      try {
        final CharSequence encryptedMessage = mE2EEStrip.encryptMessage(
                mInputEditText.getText().toString(),
                chosenContact.getSignalProtocolAddress(),
                encodingMethod
        );
        Log.d(TAG, "encryptMessage => " + encryptedMessage);

        if (encryptedMessage != null) {
          mInputEditText.setText(encryptedMessage);
          sendEncryptedMessageToApplication(encryptedMessage);
        } else {
          Toast.makeText(getContext(), INFO_MESSAGE_ENCRYPTION_FAILED, Toast.LENGTH_SHORT).show();
          Log.e(TAG, "Error: Encrypted message is null!");
        }
      } catch (TooManyCharsException e) {
        Log.e(TAG, "TooManyCharsException => " + e.getMessage(), e);
        Toast.makeText(getContext(), e.getMessage(), Toast.LENGTH_LONG).show();
      } catch (IOException e) {
        Log.e(TAG, "IOException => encryption failed", e);
        Toast.makeText(getContext(), INFO_MESSAGE_ENCRYPTION_FAILED, Toast.LENGTH_SHORT).show();
      }
    } else {
      Log.d(TAG, "No text in inputEditText => cannot encrypt");
      Toast.makeText(getContext(), INFO_NO_MESSAGE_TO_ENCRYPT, Toast.LENGTH_SHORT).show();
    }
    showChosenContactInMainInfoField();
  }

  private void createButtonDecryptClickListener() {
    if (mDecryptButton == null) return;
    mDecryptButton.setOnClickListener(v -> {
      Log.d(TAG, "DecryptButton clicked => decryptMessageInClipboard()");
      decryptMessageInClipboard();
    });
  }

  private void createButtonRecipientClickListener() {
    if (mRecipientButton != null) {
      mRecipientButton.setOnClickListener(v -> {
        Log.d(TAG, "RecipientButton clicked => loadContactsIntoContactsListView");
        loadContactsIntoContactsListView();
        showOnlyUIView(UIView.CONTACT_LIST_VIEW);
      });
    }
  }

  private void showOnlyUIView(final UIView uiView) {
    if (mLayoutE2EEMainView == null
            || mLayoutE2EEAddContactView == null
            || mLayoutE2EEContactListView == null
            || mLayoutE2EEMessagesListView == null) {
      Log.e(TAG, "showOnlyUIView => Some layout is null => cannot proceed");
      return;
    }

    Log.d(TAG, "showOnlyUIView => " + uiView.name());
    if (uiView == UIView.MAIN_VIEW) {
      mLayoutE2EEMainView.setVisibility(VISIBLE);
      mLayoutE2EEAddContactView.setVisibility(GONE);
      mLayoutE2EEContactListView.setVisibility(GONE);
      mLayoutE2EEMessagesListView.setVisibility(GONE);
      mLayoutE2EEHelpView.setVisibility(GONE);
      mLayoutE2EEVerifyContactView.setVisibility(GONE);
    } else if (uiView == UIView.ADD_CONTACT_VIEW) {
      mLayoutE2EEMainView.setVisibility(GONE);
      mLayoutE2EEAddContactView.setVisibility(VISIBLE);
      mLayoutE2EEContactListView.setVisibility(GONE);
      mLayoutE2EEMessagesListView.setVisibility(GONE);
      mLayoutE2EEHelpView.setVisibility(GONE);
      mLayoutE2EEVerifyContactView.setVisibility(GONE);
    } else if (uiView == UIView.CONTACT_LIST_VIEW) {
      mLayoutE2EEMainView.setVisibility(GONE);
      mLayoutE2EEAddContactView.setVisibility(GONE);
      mLayoutE2EEContactListView.setVisibility(VISIBLE);
      mLayoutE2EEMessagesListView.setVisibility(GONE);
      mLayoutE2EEHelpView.setVisibility(GONE);
      mLayoutE2EEVerifyContactView.setVisibility(GONE);
    } else if (uiView == UIView.MESSAGES_LIST_VIEW) {
      mLayoutE2EEMainView.setVisibility(GONE);
      mLayoutE2EEAddContactView.setVisibility(GONE);
      mLayoutE2EEContactListView.setVisibility(GONE);
      mLayoutE2EEMessagesListView.setVisibility(VISIBLE);
      mLayoutE2EEHelpView.setVisibility(GONE);
      mLayoutE2EEVerifyContactView.setVisibility(GONE);
    } else if (uiView == UIView.HELP_VIEW) {
      mLayoutE2EEMainView.setVisibility(GONE);
      mLayoutE2EEAddContactView.setVisibility(GONE);
      mLayoutE2EEContactListView.setVisibility(GONE);
      mLayoutE2EEMessagesListView.setVisibility(GONE);
      mLayoutE2EEHelpView.setVisibility(VISIBLE);
      mLayoutE2EEVerifyContactView.setVisibility(GONE);
    } else if (uiView == UIView.VERIFY_CONTACT_VIEW) {
      mLayoutE2EEMainView.setVisibility(GONE);
      mLayoutE2EEAddContactView.setVisibility(GONE);
      mLayoutE2EEContactListView.setVisibility(GONE);
      mLayoutE2EEMessagesListView.setVisibility(GONE);
      mLayoutE2EEHelpView.setVisibility(GONE);
      mLayoutE2EEVerifyContactView.setVisibility(VISIBLE);
    }
  }

  private void createButtonClearUserInputClickListener() {
    if (mClearUserInputButton == null) return;
    mClearUserInputButton.setOnClickListener(v -> {
      Log.d(TAG, "ClearUserInputButton clicked => clearUserInputString()");
      clearUserInputString();
    });
  }

  private void createButtonSelectEncryptionMethodClickListener() {
    if (mSelectEncodingFairyTaleButton == null || mSelectEncodingRawButton == null) return;

    mSelectEncodingFairyTaleButton.setOnClickListener(v -> {
      Log.d(TAG, "SelectEncodingFairyTaleButton clicked => switching to RAW");
      mSelectEncodingFairyTaleButton.setVisibility(GONE);
      mSelectEncodingRawButton.setVisibility(VISIBLE);
      encodingMethod = Encoder.RAW;
    });

    mSelectEncodingRawButton.setOnClickListener(v -> {
      Log.d(TAG, "SelectEncodingRawButton clicked => switching to FAIRYTALE");
      mSelectEncodingFairyTaleButton.setVisibility(VISIBLE);
      mSelectEncodingRawButton.setVisibility(GONE);
      encodingMethod = Encoder.FAIRYTALE;
    });
  }

  private void createButtonShowHelpClickListener() {
    if (mShowHelpButton == null) return;
    mShowHelpButton.setOnClickListener(v -> {
      Log.d(TAG, "ShowHelpButton clicked => showOnlyUIView(HELP_VIEW)");
      showOnlyUIView(UIView.HELP_VIEW);
    });
  }

  private void createButtonChatLogsClickListener() {
    if (mChatLogsButton == null) return;
    mChatLogsButton.setOnClickListener(v -> {
      Log.d(TAG, "ChatLogsButton clicked => loadMessagesIntoMessagesListView => MESSAGES_LIST_VIEW");
      refreshContactInMessageInfoField();
      loadMessagesIntoMessagesListView();
      showOnlyUIView(UIView.MESSAGES_LIST_VIEW);
    });
  }

  private void setupMessageInputEditTextField() {
    mInputEditText.setMovementMethod(new ScrollingMovementMethod());
    mInputEditText.setOnFocusChangeListener((v, hasFocus) -> {
      if (hasFocus) {
        Log.d(TAG, "Focus on inputEditText => setOtherIC");
        mRichInputConnection.setOtherIC(mInputEditText);
      }
      mRichInputConnection.setShouldUseOtherIC(hasFocus);
      changeVisibilityInputFieldButtons(hasFocus);
    });

    mClearUserInputButton.setVisibility(GONE);
    mSelectEncodingFairyTaleButton.setVisibility(GONE);
  }

  private void sendPreKeyResponseMessageToApplication() {
    Log.d(TAG, "sendPreKeyResponseMessageToApplication called");
    final String encoded;
    final String message = mE2EEStrip.getPreKeyResponseMessage();
    try {
      mE2EEStrip.checkMessageLengthForEncodingMethod(message, encodingMethod, true);
      encoded = mE2EEStrip.encode(message, encodingMethod);
    } catch (TooManyCharsException e) {
      Log.e(TAG, "TooManyCharsException => " + e.getMessage(), e);
      Toast.makeText(getContext(), e.getMessage(), Toast.LENGTH_LONG).show();
      return;
    } catch (IOException e) {
      Log.e(TAG, "IOException => Generating pre key message failed!", e);
      Toast.makeText(getContext(), "Generating pre key message failed!", Toast.LENGTH_SHORT).show();
      return;
    }
    mInputEditText.setText(encoded);
    sendEncryptedMessageToApplication(encoded);
  }

  private void decryptMessageInClipboard() {
    Log.d(TAG, "decryptMessageInClipboard called");
    final CharSequence mEncryptedMessageFromClipboard = mE2EEStrip.getEncryptedMessageFromClipboard();
    if (mEncryptedMessageFromClipboard == null || mEncryptedMessageFromClipboard.length() == 0) {
      Toast.makeText(getContext(), INFO_NO_MESSAGE_TO_DECRYPT, Toast.LENGTH_SHORT).show();
      Log.d(TAG, "No message in clipboard => cannot decrypt");
      return;
    }

    try {
      final String encodedMessage = mE2EEStrip.decodeMessage(mEncryptedMessageFromClipboard.toString());
      if (encodedMessage == null) {
        Log.d(TAG, "encodedMessage is null => cannot decrypt");
        return;
      }

      final MessageEnvelope messageEnvelope = JsonUtil.fromJson(encodedMessage, MessageEnvelope.class);
      if (messageEnvelope == null) throw new IOException("Message is null. Abort!");

      final MessageType messageType = mE2EEStrip.getMessageType(messageEnvelope);
      if (messageType == null) throw new IOException("Message type is null. Abort!");

      final Contact extractedSender = (Contact) mE2EEStrip.getContactFromEnvelope(messageEnvelope);
      if (messageEnvelope.getSignalProtocolAddressName().equals(mE2EEStrip.getAccountName())) {
        Toast.makeText(getContext(), INFO_CANNOT_DECRYPT_OWN_MESSAGES, Toast.LENGTH_SHORT).show();
        mE2EEStrip.clearClipboard();
        showChosenContactInMainInfoField();
        return;
      }

      if (messageType.equals(MessageType.PRE_KEY_RESPONSE_MESSAGE)) {
        processPreKeyResponse(messageEnvelope, extractedSender);
      } else if (messageType.equals(MessageType.SIGNAL_MESSAGE)) {
        processSignalMessage(messageEnvelope, extractedSender);
      } else if (messageType.equals(MessageType.UPDATED_PRE_KEY_RESPONSE_MESSAGE_AND_SIGNAL_MESSAGE)) {
        processUpdatedPreKeyResponse(messageEnvelope, extractedSender);
      }
    } catch (IOException e) {
      Log.e(TAG, "Error decrypting message from clipboard", e);
      resetChosenContactAndInfoText();
    }
    showChosenContactInMainInfoField();
    mE2EEStrip.clearClipboard();
    changeImageButtonState(mDecryptButton, ButtonState.DISABLED);
  }

  private void processSignalMessage(MessageEnvelope messageEnvelope, Contact sender) {
    Log.d(TAG, "processSignalMessage => sender=" + sender);
    if (sender == null) {
      Toast.makeText(getContext(), INFO_SIGNAL_MESSAGE_NO_CONTACT_FOUND, Toast.LENGTH_SHORT).show();
      showAddContactView(messageEnvelope);
    } else {
      chosenContact = sender;
      setInfoTextViewMessage(
              mInfoTextView,
              "Detected contact: " + chosenContact.getFirstName() + " " + chosenContact.getLastName()
      );
      decryptMessageAndShowMessageInMainInputField(messageEnvelope, chosenContact, false);
    }
  }

  private void processPreKeyResponse(MessageEnvelope messageEnvelope, Contact sender) {
    Log.d(TAG, "processPreKeyResponse => sender=" + sender);
    setInfoTextViewMessage(mInfoTextView, INFO_PRE_KEY_DETECTED);
    if (sender == null) {
      showAddContactView(messageEnvelope);
    } else {
      chosenContact = sender;
      setInfoTextViewMessage(
              mInfoTextView,
              "Detected contact: " + chosenContact.getFirstName() + " " + chosenContact.getLastName()
      );
      decryptMessageAndShowMessageInMainInputField(messageEnvelope, chosenContact, true);
    }
  }

  private void processUpdatedPreKeyResponse(MessageEnvelope messageEnvelope, Contact sender) {
    Log.d(TAG, "processUpdatedPreKeyResponse => sender=" + sender);
    if (sender == null) {
      processPreKeyResponse(messageEnvelope, sender);
    } else {
      chosenContact = sender;
      setInfoTextViewMessage(
              mInfoTextView,
              "Detected contact with updated keybundle: "
                      + chosenContact.getFirstName()
                      + " "
                      + chosenContact.getLastName()
      );
      decryptMessageAndShowMessageInMainInputField(messageEnvelope, chosenContact, false);
    }
  }

  private void resetChosenContactAndInfoText() {
    Log.d(TAG, "resetChosenContactAndInfoText => chosenContact=null");
    chosenContact = null;
    setInfoTextViewMessage(mInfoTextView, INFO_NO_CONTACT_CHOSEN);
  }

  private void showAddContactView(MessageEnvelope messageEnvelope) {
    Log.d(TAG, "showAddContactView => createAddContactAddClickListener");
    createAddContactAddClickListener(messageEnvelope);
    showOnlyUIView(UIView.ADD_CONTACT_VIEW);
  }

  private void decryptMessageAndShowMessageInMainInputField(
          final MessageEnvelope messageEnvelope,
          final Contact sender,
          boolean isSessionCreation
  ) {
    Log.d(TAG, "decryptMessageAndShowMessageInMainInputField => isSessionCreation=" + isSessionCreation);
    final CharSequence decryptedMessage = mE2EEStrip.decryptMessage(messageEnvelope, sender);

    if (!isSessionCreation && decryptedMessage != null) {
      Log.d(TAG, "DecryptedMessage => " + decryptedMessage);
      mInputEditText.setText(decryptedMessage);
      changeVisibilityInputFieldButtons(true);
    } else if (isSessionCreation) {
      Log.d(TAG, "Session creation => no final display of message");
      changeVisibilityInputFieldButtons(true);
    } else {
      Toast.makeText(getContext(), INFO_MESSAGE_DECRYPTION_FAILED, Toast.LENGTH_LONG).show();
      Log.e(TAG, "Error: Decrypted message is null");
    }
    mE2EEStrip.clearClipboard();
  }

  private void sendEncryptedMessageToApplication(CharSequence encryptedMessage) {
    if (encryptedMessage == null) return;

    Log.d(TAG, "sendEncryptedMessageToApplication => " + encryptedMessage);
    mRichInputConnection.setShouldUseOtherIC(false);
    mListener.onTextInput((String) encryptedMessage);
    mInputEditText.clearFocus();
    clearUserInputString();
    mE2EEStrip.clearClipboard();
  }

  private void clearUserInputString() {
    Log.d(TAG, "clearUserInputString => setting inputEditText to empty");
    if (mInputEditText != null) {
      mInputEditText.setText("");
    }
  }

  private void changeVisibilityInputFieldButtons(boolean shouldBeVisible) {
    Log.d(TAG, "changeVisibilityInputFieldButtons => " + shouldBeVisible);
    if (mClearUserInputButton != null
            && mSelectEncodingFairyTaleButton != null
            && mSelectEncodingRawButton != null) {
      if (shouldBeVisible) {
        mClearUserInputButton.setVisibility(VISIBLE);
        if (encodingMethod.equals(Encoder.FAIRYTALE)) {
          mSelectEncodingFairyTaleButton.setVisibility(VISIBLE);
        } else {
          mSelectEncodingRawButton.setVisibility(VISIBLE);
        }
      } else {
        mClearUserInputButton.setVisibility(GONE);
        mSelectEncodingFairyTaleButton.setVisibility(GONE);
        mSelectEncodingRawButton.setVisibility(GONE);
      }
    }
  }

  private void showChosenContactInMainInfoField() {
    if (chosenContact != null) {
      setInfoTextViewMessage(
              mInfoTextView,
              "Chosen contact: " + chosenContact.getFirstName()
                      + " " + chosenContact.getLastName()
      );
    } else {
      setInfoTextViewMessage(mInfoTextView, INFO_NO_CONTACT_CHOSEN);
    }
  }

  private enum ButtonState {ENABLED, DISABLED}

  private enum UIView {
    MAIN_VIEW, ADD_CONTACT_VIEW, CONTACT_LIST_VIEW, MESSAGES_LIST_VIEW, HELP_VIEW, VERIFY_CONTACT_VIEW
  }

  @Override
  public void selectContact(Contact contact) {
    Log.d(TAG, "selectContact => " + contact);
    chosenContact = contact;
    showChosenContactInMainInfoField();
    showOnlyUIView(UIView.MAIN_VIEW);
  }

  @Override
  public void removeContact(Contact contact) {
    Log.d(TAG, "removeContact => " + contact);
    mE2EEStrip.removeContact(contact);
    loadContactsIntoContactsListView();
    resetChosenContactAndInfoText();
  }

  @Override
  public void verifyContact(Contact contact) {
    Log.d(TAG, "verifyContact => " + contact);
    chosenContact = contact;
    loadFingerprintInVerifyContactView();
    showOnlyUIView(UIView.VERIFY_CONTACT_VIEW);
  }

  public void setRichInputConnection(RichInputConnection richInputConnection) {
    Log.d(TAG, "setRichInputConnection => set");
    mRichInputConnection = richInputConnection;
  }

  public void clearFocusEditTextView() {
    Log.d(TAG, "clearFocusEditTextView => clearing focus");
    if (mInputEditText != null) {
      mInputEditText.clearFocus();
    }
  }

  public void setListener(final Listener listener, final View inputView) {
    Log.d(TAG, "setListener => set");
    mListener = listener;
    mMainKeyboardView = inputView.findViewById(R.id.keyboard_view);
  }

  public void clear() {
    Log.d(TAG, "clear => removing all views from mE2EEMainStrip");
    mE2EEMainStrip.removeAllViews();
    mE2EEStripVisibilityGroup.showE2EEStrip();
  }

  public interface Listener {
    void onTextInput(final String rawText);
  }
}
