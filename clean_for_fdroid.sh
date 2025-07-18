#!/bin/bash

# Script de limpieza para F-Droid
# Elimina archivos innecesarios que podrían causar problemas en F-Droid

echo "🧹 Limpiando proyecto para F-Droid..."

# Limpiar directorios de build
echo "📁 Limpiando directorios de build..."
rm -rf app/build/
rm -rf build/
rm -rf .gradle/
rm -rf */build/

# Limpiar archivos temporales
echo "🗑️ Eliminando archivos temporales..."
find . -name "*.tmp" -delete
find . -name "*.temp" -delete
find . -name "*.cache" -delete
find . -name "*.bak" -delete
find . -name "*.backup" -delete
find . -name "*~" -delete

# Limpiar archivos nativos problemáticos
echo "🔧 Eliminando archivos nativos problemáticos..."
find . -name "*.dll" -delete
find . -name "*.dylib" -delete
find . -name "*.so.debug" -delete
find . -name "*_debug.so" -delete
find . -name "*_testing.so" -delete
find . -name "*_unstripped.so" -delete
find . -name "*_testing_*.dylib" -delete
find . -name "*_testing_*.dll" -delete
find . -name "libsignal_jni_aarch64.dylib" -delete
find . -name "libsignal_jni_amd64.dylib" -delete
find . -name "signal_jni_*.dll" -delete

# Limpiar directorios de bibliotecas nativas problemáticas
echo "🔧 Limpiando directorios de bibliotecas nativas..."
rm -rf .gradle/caches/modules-2/files-2.1/*/libsignal-android/*/
rm -rf app/build/intermediates/merged_native_libs/
rm -rf app/build/intermediates/stripped_native_libs/

# Limpiar archivos de debug
echo "🐛 Eliminando archivos de debug..."
find . -name "*.debug" -delete
find . -name "*.pdb" -delete
find . -name "*.symbols" -delete
find . -name "*.map" -delete

# Limpiar archivos de sistema
echo "🖥️ Eliminando archivos de sistema..."
find . -name ".DS_Store" -delete
find . -name "Thumbs.db" -delete
find . -name "Desktop.ini" -delete

# Limpiar archivos de IDE
echo "💻 Limpiando archivos de IDE..."
rm -rf .idea/workspace.xml
rm -rf .idea/tasks.xml
rm -rf .idea/gradle.xml
rm -rf .idea/assetWizardSettings.xml
rm -rf .idea/dictionaries
rm -rf .idea/libraries
rm -rf .idea/caches

# Limpiar archivos de lint
echo "🔍 Limpiando archivos de lint..."
rm -rf lint/intermediates/
rm -rf lint/generated/
rm -rf lint/outputs/
rm -rf lint/tmp/

# Limpiar archivos de signing
echo "🔑 Eliminando archivos de signing..."
find . -name "*.keystore" -delete
find . -name "*.jks" -delete
find . -name "key.properties" -delete

# Verificar que no existen archivos problemáticos
echo "🔍 Verificando archivos problemáticos..."
if find . -name "*.dll" -o -name "*.dylib" -o -name "*_debug.so" -o -name "*_testing.so" | grep -q .; then
    echo "⚠️ Advertencia: Aún existen archivos problemáticos"
    find . -name "*.dll" -o -name "*.dylib" -o -name "*_debug.so" -o -name "*_testing.so"
else
    echo "✅ No se encontraron archivos problemáticos"
fi

# Mostrar tamaño del proyecto
echo "📊 Tamaño del proyecto:"
du -sh . 2>/dev/null || echo "No se pudo calcular el tamaño"

echo "✅ Limpieza completada. El proyecto está listo para F-Droid!"
echo ""
echo "🚀 Comandos sugeridos para F-Droid:"
echo "   ./gradlew clean"
echo "   ./gradlew assembleRelease"
echo ""
echo "📝 Recuerda verificar que todas las dependencias son compatibles con F-Droid" 