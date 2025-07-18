#!/bin/bash

# Script para firmar el APK optimizado de 29MB
# Uso: ./sign_apk.sh [password_del_keystore]

KEYSTORE_PATH="/Users/sirh0f/Dev/KeysActualizadasAgosto2025"
KEYSTORE_ALIAS="release"
UNSIGNED_APK="app/build/outputs/apk/release/SecureChatKeyboard-release-20250719.apk"
SIGNED_APK="SecureChatKeyboard-release-SIGNED.apk"

# Verificar que existe el APK sin firmar
if [ ! -f "$UNSIGNED_APK" ]; then
    echo "❌ Error: No se encuentra el APK sin firmar"
    echo "Ejecuta primero: ./gradlew clean assembleRelease"
    exit 1
fi

# Verificar que existe el keystore
if [ ! -f "$KEYSTORE_PATH" ]; then
    echo "❌ Error: No se encuentra el keystore en $KEYSTORE_PATH"
    exit 1
fi

# Obtener password
if [ -z "$1" ]; then
    echo "Ingresa el password del keystore:"
    read -s KEYSTORE_PASSWORD
else
    KEYSTORE_PASSWORD="$1"
fi

echo "🔑 Firmando APK optimizado..."

# Firmar el APK con apksigner (sin comillas en el password)
/Users/sirh0f/Library/Android/sdk/build-tools/35.0.0/apksigner sign \
    --ks "$KEYSTORE_PATH" \
    --ks-pass pass:$KEYSTORE_PASSWORD \
    --ks-key-alias "$KEYSTORE_ALIAS" \
    --out "$SIGNED_APK" \
    "$UNSIGNED_APK"

# Verificar la firma
/Users/sirh0f/Library/Android/sdk/build-tools/35.0.0/apksigner verify --verbose "$SIGNED_APK"

if [ $? -eq 0 ]; then
    echo "✅ APK firmado exitosamente: $SIGNED_APK"
    echo "📊 Tamaño del APK firmado:"
    ls -lh "$SIGNED_APK"
    echo ""
    echo "🚀 Para F-Droid usar: $SIGNED_APK"
else
    echo "❌ Error al firmar el APK"
    exit 1
fi 