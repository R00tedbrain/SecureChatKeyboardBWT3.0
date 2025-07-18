# 🚀 Guía para F-Droid - SecureChats Keyboard BWT 3.0

## 🔧 Problemas Resueltos

Esta guía documenta los cambios realizados para resolver los problemas con archivos innecesarios que F-Droid detectaba en el APK.

### ⚠️ Problema Original
F-Droid detectaba archivos dll y dylib innecesarios en el APK, así como bibliotecas nativas de debug y testing que no son necesarias para la versión de producción.

### ✅ Soluciones Implementadas

#### 1. **Filtrado de Arquitecturas Nativas**
- **Archivo**: `app/build.gradle`
- **Cambio**: Limitado a solo arquitecturas ARM necesarias
```gradle
ndk {
    abiFilters 'arm64-v8a', 'armeabi-v7a'
}
```

#### 2. **Exclusión de Archivos Innecesarios**
- **Archivo**: `app/build.gradle`
- **Cambio**: Agregado `packagingOptions` para excluir archivos problemáticos
```gradle
packagingOptions {
    exclude 'lib/*/libsignal_jni_testing.so'
    exclude 'lib/*/libsignal_jni_debug.so'
    exclude 'lib/*/libsignal_jni_unstripped.so'
    // ... más exclusiones
}
```

#### 3. **Eliminación de Dependencias Duplicadas**
- **Archivo**: `app/build.gradle`
- **Cambio**: Removido `protobuf-javalite` duplicado
- **Reorganización**: Dependencias agrupadas lógicamente

#### 4. **Optimización de ProGuard**
- **Archivo**: `app/proguard-rules.pro`
- **Cambio**: Reglas optimizadas para reducir tamaño del APK
- **Agregado**: Eliminación de logs de debug y código innecesario

#### 5. **Configuración de F-Droid**
- **Archivo**: `fdroid/build.yml`
- **Cambio**: Agregado prebuild para limpiar archivos problemáticos
- **Agregado**: Configuración para build reproducible

#### 6. **Script de Limpieza**
- **Archivo**: `clean_for_fdroid.sh`
- **Nuevo**: Script automático para limpiar archivos problemáticos
- **Función**: Elimina archivos innecesarios antes del build

## 🛠️ Cómo Usar

### Preparación para F-Droid:
```bash
# 1. Ejecutar script de limpieza
./clean_for_fdroid.sh

# 2. Limpiar proyecto
./gradlew clean

# 3. Generar APK de release
./gradlew assembleRelease
```

### Verificación Manual:
```bash
# Verificar que no existen archivos problemáticos
find . -name "*.dll" -o -name "*.dylib" -o -name "*_debug.so" -o -name "*_testing.so"

# Verificar tamaño del APK
ls -lh app/build/outputs/apk/release/
```

## 📊 Reducción de Tamaño

### Antes de la Optimización:
- APK incluía múltiples arquitecturas innecesarias
- Bibliotecas de debug y testing incluidas
- Archivos de metadatos redundantes

### Después de la Optimización:
- ✅ Solo arquitecturas ARM necesarias
- ✅ Sin bibliotecas de debug/testing
- ✅ Archivos de metadatos limpiados
- ✅ Dependencias optimizadas

## 🔍 Archivos Modificados

### Archivos Principales:
- `app/build.gradle` - Configuración principal optimizada
- `app/proguard-rules.pro` - Reglas de optimización
- `fdroid/build.yml` - Configuración de F-Droid
- `build.gradle` - Configuración global
- `.gitignore` - Exclusiones mejoradas

### Archivos Nuevos:
- `clean_for_fdroid.sh` - Script de limpieza
- `F-DROID_GUIDE.md` - Esta guía

## 🚨 Importante

### ⚠️ Mantener Funcionalidad:
- ✅ Todas las funciones criptográficas intactas
- ✅ Protocolo Signal funcional
- ✅ Criptografía post-cuántica activa
- ✅ Todas las traducciones preservadas

### 🔧 Verificaciones antes del Release:
1. Ejecutar tests: `./gradlew test`
2. Verificar funcionalidad E2EE
3. Probar en diferentes dispositivos ARM
4. Verificar que no hay archivos problemáticos

## 📝 Notas para F-Droid

### Dependencias Justificadas:
- **libsignal-android**: E2EE esencial
- **Bouncy Castle**: Criptografía post-cuántica
- **Jackson**: Serialización JSON segura
- **Security Crypto**: Almacenamiento cifrado

### Bibliotecas Nativas:
- Solo `libsignal_jni.so` para ARM
- Solo `libzkgroup.so` para ARM  
- Sin bibliotecas de debug/testing

### Configuración Reproducible:
- Versiones fijas de dependencias
- Build determinístico
- Sin archivos temporales

## 🎯 Resultado

Con estos cambios, el APK debería ser aceptado por F-Droid sin problemas relacionados con archivos innecesarios. El tamaño del APK se ha reducido significativamente manteniendo toda la funcionalidad esencial.

## 📞 Soporte

Si F-Droid reporta nuevos problemas:
1. Ejecutar `./clean_for_fdroid.sh`
2. Verificar que no hay archivos problemáticos
3. Revisar logs de F-Droid para errores específicos
4. Ajustar `packagingOptions` según necesidad 