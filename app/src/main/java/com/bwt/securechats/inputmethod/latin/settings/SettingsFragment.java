package com.bwt.securechats.inputmethod.latin.settings;

import android.os.Bundle;
import android.preference.PreferenceScreen;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListView;

import com.bwt.securechats.inputmethod.R;
import com.bwt.securechats.inputmethod.latin.utils.ApplicationUtils;

public final class SettingsFragment extends InputMethodSettingsFragment {
  @Override
  public void onCreate(final Bundle icicle) {
    super.onCreate(icicle);
    setHasOptionsMenu(true);
    // Carga la definición de preferencias (prefs.xml)
    addPreferencesFromResource(R.xml.prefs);

    // Ajusta el título del PreferenceScreen
    final PreferenceScreen preferenceScreen = getPreferenceScreen();
    preferenceScreen.setTitle(
            ApplicationUtils.getActivityTitleResId(getActivity(), SettingsActivity.class)
    );
  }

  @Override
  public View onCreateView(LayoutInflater inflater, ViewGroup container,
                           Bundle savedInstanceState) {
    // 1) Infla la vista por defecto del PreferenceFragment,
    //    donde ya se muestra la lista de preferencias
    View rootView = super.onCreateView(inflater, container, savedInstanceState);

    // 2) Localiza la ListView interna que contiene las preferencias
    ListView listView = rootView.findViewById(android.R.id.list);

    // 3) Infla tu layout footer con la imagen (footer_image.xml)
    View footerView = inflater.inflate(R.layout.footer_image, listView, false);

    // 4) Añade el footer a la lista de preferencias
    listView.addFooterView(footerView, null, false);

    return rootView;
  }
}
