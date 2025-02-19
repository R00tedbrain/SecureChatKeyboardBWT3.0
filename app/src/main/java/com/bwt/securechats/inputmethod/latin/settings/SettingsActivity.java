/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bwt.securechats.inputmethod.latin.settings;

import android.app.ActionBar;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;  // <--- Import necesario
import android.os.Bundle;
import android.preference.PreferenceActivity;
import android.util.Log;
import android.view.MenuItem;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.Toast;

import com.bwt.securechats.inputmethod.R;
import com.bwt.securechats.inputmethod.latin.utils.FragmentUtils;

public class SettingsActivity extends PreferenceActivity {
  private static final String DEFAULT_FRAGMENT = SettingsFragment.class.getName();
  private static final String TAG = SettingsActivity.class.getSimpleName();

  // INICIO BLOQUE VALIDACIÓN
  // Puedes modificar estas claves según lo que necesites
  private static final String[] VALID_KEYS = {
          "X2btzANsU5Ra#azJ@zG",
          "@Hf&iM^tJ*4zmuV2tK!",
          "MM3&8TAojDxSFc5uS&Z",
          "ufn&q4RxJMm8W4u4Mas",
          "tKb@Ln8!vRqPyXFNDSs"
  };
  // FIN BLOQUE VALIDACIÓN

  @Override
  protected void onStart() {
    super.onStart();

    // INICIO BLOQUE VALIDACIÓN
    // 1. Comprobamos si la app ya está activada. De no estarlo, pedimos la clave.
    if (!isAppActivated()) {
      showActivationDialog();
      return; // Salimos para que no siga con el resto hasta que se active.
    }
    // FIN BLOQUE VALIDACIÓN

    boolean enabled = false;
    try {
      enabled = isInputMethodOfThisImeEnabled();
    } catch (Exception e) {
      Log.e(TAG, "Exception in check if input method is enabled", e);
    }

    if (!enabled) {
      final Context context = this;
      AlertDialog.Builder builder = new AlertDialog.Builder(this);
      builder.setMessage(R.string.setup_message);
      builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
        public void onClick(DialogInterface dialog, int id) {
          Intent intent = new Intent(android.provider.Settings.ACTION_INPUT_METHOD_SETTINGS);
          intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
          context.startActivity(intent);
          dialog.dismiss();
        }
      });
      builder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
        public void onClick(DialogInterface dialog, int id) {
          finish();
        }
      });
      builder.setCancelable(false);

      builder.create().show();
    }
  }

  /**
   * Check if this IME is enabled in the system.
   *
   * @return whether this IME is enabled in the system.
   */
  private boolean isInputMethodOfThisImeEnabled() {
    final InputMethodManager imm =
            (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
    final String imePackageName = getPackageName();
    for (final InputMethodInfo imi : imm.getEnabledInputMethodList()) {
      if (imi.getPackageName().equals(imePackageName)) {
        return true;
      }
    }
    return false;
  }

  @Override
  protected void onCreate(final Bundle savedState) {
    super.onCreate(savedState);
    final ActionBar actionBar = getActionBar();
    if (actionBar != null) {
      actionBar.setDisplayHomeAsUpEnabled(true);
      actionBar.setHomeButtonEnabled(true);
    }
  }

  @Override
  public boolean onOptionsItemSelected(final MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      super.onBackPressed();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }

  @Override
  public Intent getIntent() {
    final Intent intent = super.getIntent();
    final String fragment = intent.getStringExtra(EXTRA_SHOW_FRAGMENT);
    if (fragment == null) {
      intent.putExtra(EXTRA_SHOW_FRAGMENT, DEFAULT_FRAGMENT);
    }
    intent.putExtra(EXTRA_NO_HEADERS, true);
    return intent;
  }

  @Override
  public boolean isValidFragment(final String fragmentName) {
    return FragmentUtils.isValidFragment(fragmentName);
  }

  // INICIO BLOQUE VALIDACIÓN

  // Método para saber si la app ya está activada (clave introducida correctamente).
  private boolean isAppActivated() {
    SharedPreferences prefs = getSharedPreferences("MyPrefs", MODE_PRIVATE);
    return prefs.getBoolean("isActivated", false);
  }

  // Muestra un AlertDialog con un EditText donde el usuario introduce la clave.
  private void showActivationDialog() {
    final EditText input = new EditText(this);
    input.setHint("Introduzca la clave");

    new AlertDialog.Builder(this)
            .setTitle("Activación")
            .setMessage("Por favor, introduzca una de las claves válidas:")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("OK", (dialog, which) -> {
              String userKey = input.getText().toString().trim();
              if (checkKey(userKey)) {
                setAppActivated();
                Toast.makeText(this, "Activación correcta", Toast.LENGTH_SHORT).show();
                // No llamamos finish() aquí para permitir que la actividad continúe
                dialog.dismiss();
              } else {
                Toast.makeText(this, "Clave incorrecta", Toast.LENGTH_SHORT).show();
                // Finaliza la actividad para que no pueda usarse sin clave
                finish();
              }
            })
            .show();
  }

  // Comprueba si la clave introducida coincide con alguna de las válidas
  private boolean checkKey(String enteredKey) {
    for (String validKey : VALID_KEYS) {
      if (validKey.equals(enteredKey)) {
        return true;
      }
    }
    return false;
  }

  // Guarda en SharedPreferences que la app está activada
  private void setAppActivated() {
    SharedPreferences prefs = getSharedPreferences("MyPrefs", MODE_PRIVATE);
    prefs.edit().putBoolean("isActivated", true).apply();
  }
  // FIN BLOQUE VALIDACIÓN
}
