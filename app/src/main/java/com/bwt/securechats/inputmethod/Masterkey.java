package com.bwt.securechats.inputmethod;

import android.content.Context;
import android.util.Log;

import androidx.security.crypto.MasterKey;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Clase auxiliar que gestiona la MasterKey para EncryptedSharedPreferences.
 */
public class Masterkey {
    private static final String TAG = "Masterkey_DEBUG";
    private static MasterKey mainKey;

    /**
     * Devuelve (y en caso necesario crea) una MasterKey AES256_GCM.
     */
    public static MasterKey getMasterKey(Context context) {
        if (mainKey == null) {
            try {
                mainKey = new MasterKey.Builder(context)
                        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                        .build();
                Log.d(TAG, "MasterKey creada correctamente");
            } catch (GeneralSecurityException | IOException e) {
                Log.e(TAG, "Error creando la MasterKey", e);
                return null;
            }
        }
        return mainKey;
    }
}
