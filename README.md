# 🔐 SecureChats Keyboard BWT 2.0.0

<div align="center">
  <img src="https://github.com/user-attachments/assets/5a517fa3-29bd-453f-9242-65a7aa058c79" alt="icono" width="600" />
  
  <br><br>
  
  <a href="https://play.google.com/store/apps/details?id=com.bwt.securechats&hl=es">
    <img src="https://play.google.com/intl/en_us/badges/static/images/badges/es_badge_web_generic.png" alt="Disponible en Google Play" width="250"/>
  </a>
</div>
<div align="center">
  <a href="https://www.youtube.com/shorts/q_wTsI0SYmg">
    <img src="https://img.youtube.com/vi/q_wTsI0SYmg/0.jpg" alt="Mira el vídeo" width="600" />
  </a>
</div>


<img width="1551" alt="Captura de pantalla 2025-06-09 a las 17 40 52" src="https://github.com/user-attachments/assets/9d02e271-65fb-44da-92c9-a505952da667" />


<img width="1555" alt="Captura de pantalla 2025-06-09 a las 17 40 24" src="https://github.com/user-attachments/assets/f5039166-b0dd-4614-ac60-caa412e3d123" />

<img width="1555" alt="Captura de pantalla 2025-06-09 a las 17 39 49" src="https://github.com/user-attachments/assets/80f09300-9157-4e9d-a229-7c6ed0efeec1" />

## English

### 🌟 Advanced Post-Quantum Secure Keyboard for Android

**SecureChats Keyboard BWT 2.0.0** is an enhanced version of the innovative KryptEY Android keyboard, originally created by **mellitopia** and **amnesica**. This advanced iteration integrates **end-to-end encryption (E2EE)** with **post-quantum cryptography** resistance, built on the Signal Protocol foundation with enhanced **Kyber (PQC)** implementation for future-proof security against quantum computer attacks.

**🚀 What's New in BWT 2.0.0:**
- **Post-Quantum Cryptography (Kyber)** integration
- **EncryptedSharedPreferences** with AES256-GCM
- **Enhanced key rotation** (2 days vs original 30 days)
- **Per-contact history deletion** functionality
- **89+ language localizations** (vs original basic support)
- **libsignal-android 0.73.2** with latest security improvements

---

### 🔮 **Post-Quantum Cryptography (PQC) Features**

#### 🛡️ **Kyber Integration** *(New in BWT 3.0)*
- **Hybrid Encryption**: ECC (Signal Protocol) + **Kyber Post-Quantum** resistant algorithms
- **KEM Encapsulation**: Key Encapsulation Mechanism using Bouncy Castle PQC provider
- **Automatic Key Rotation**: Kyber pre-keys automatically rotate every 2 days
- **Future-Proof Security**: Protection against quantum computer attacks (Shor's algorithm)
- **Dual Pre-Key System**: Both ECC and Kyber pre-keys managed simultaneously

#### 🔄 **Enhanced Key Management** *(Improved in BWT 3.0)*
- **Faster Rotation**: Pre-keys rotate every **2 days** (vs original 30 days)
- **Smart Rotation Logic**: Independent rotation schedules for ECC and PQC keys
- **Secure Deletion**: Old keys automatically purged after use
- **Seamless Migration**: Backward compatibility with original KryptEY devices

---

### 🔒 **Enhanced Security Architecture**

#### 📱 **Encrypted Storage System** *(New in BWT 3.0)*
- **EncryptedSharedPreferences**: All user data encrypted at rest using AES256-GCM *(vs original plain SharedPreferences)*
- **MasterKey Protection**: Hardware-backed keystores where available
- **JSON Encryption**: Message history, contacts, and keys stored encrypted
- **Zero-Knowledge Design**: No plaintext data stored on device

#### 🛡️ **Signal Protocol Implementation**
- **X3DH Key Agreement Protocol**: Elliptic curve X25519 with SHA-512
- **Double Ratchet Algorithm**: Advanced key derivation and message authentication  
- **AES-256 with CBC (PKCS#7)**: Message encryption standard
- **SHA-256**: Hash function for various chains
- **SHA-512**: Fingerprint generation for public key representation
- **Perfect Forward Secrecy**: Each message uses unique encryption keys

#### 🔧 **Protocol Stores Management**
All protocol information stored in specialized stores:
- **IdentityKeyStore**: Identity key management
- **PreKeyMetadataStore**: Pre-key metadata and rotation schedules
- **PreKeyStore**: One-time pre-keys (2 keys vs Signal's 100)
- **SignedPreKeyStore**: Signed pre-key management
- **SessionStore**: Session state management
- **SenderKeyStore**: Group messaging keys
- **SignalProtocolStore**: Unified protocol interface
- **BCKyberPreKeyStore**: *(New)* Post-quantum Kyber pre-keys

---

### 📨 **Message Types & Protocol**

#### 🔄 **Four Message Types**
1. **PreKeyResponse**: Send PreKeyBundle (invite message)
2. **PreKeySignalMessage**: Send ciphertext + PreKeyBundle after session establishment
3. **SignalMessage**: Send regular ciphertext
4. **PreKeyResponse + SignalMessage**: *(Enhanced)* Send ciphertext with updated PreKeyBundle + Kyber keys

#### 📦 **MessageEnvelope Structure**
All message information collected in a **MessageEnvelope** containing:
- **PreKeyResponse**: Key bundle data (ECC + Kyber in BWT 3.0)
- **CiphertextMessage**: Encrypted message as byte array
- **CiphertextType**: Message type identifier
- **Timestamp**: Message creation time
- **SignalProtocolAddress**: Sender identification (randomized UUID)

---

### 🎭 **Steganography & Encoding**

#### 🔤 **Two Encoding Modes**
- **Raw Mode**: Direct JSON display with minified format
- **Fairy Tale Mode**: Messages hidden in invisible Unicode characters

#### 🧙‍♂️ **Fairy Tale Mode Technical Details**
- **Invisible Unicode Characters**: 16 characters (U+200C, etc.) for 4-bit mapping
- **JSON Minification**: Keys abbreviated ("preKeyResponse" → "pR")  
- **GZIP Compression**: Size optimization before encoding
- **Binary Conversion**: 4 bits mapped to invisible Unicode (0000-1111)
- **Decoy Stories**: Hidden in Cinderella or Rapunzel fairy tales
- **Full Reversibility**: Extract → Convert → Decompress → Deminify

---

### ✨ **Advanced Features**

#### 💬 **Secure Messaging**
- **End-to-End Encryption**: All messages encrypted before leaving device
- **Server-Free Operation**: No central server for key exchange *(Unlike Signal app)*
- **UUID Identification**: Randomized UUIDs instead of phone numbers
- **Real-time Encryption**: Live encryption/decryption as you type

#### 🗑️ **Privacy Controls** *(Enhanced in BWT 3.0)*
- **Per-Contact History Deletion**: *(New)* Delete message history per contact with one tap
- **Cryptographic Erasure**: *(New)* Secure deletion ensures data unrecoverability
- **Contact Management**: Add/remove contacts with verification
- **Session Management**: Secure session establishment without servers

#### 🔧 **Session Establishment Flow**
1. **Alice** generates and sends **PreKeyBundle** (invite message)
2. **Bob** adds Alice as contact, establishes session locally
3. **Bob** sends **PreKeySignalMessage** (first encrypted message)
4. **Alice** adds Bob, establishes session, decrypts message
5. Both parties exchange **SignalMessages** for ongoing conversation
6. **Key Rotation**: *(Enhanced)* Every 2 days with automatic PreKeyBundle updates

---

### 🌍 **Internationalization**

#### 🗣️ **Massive Language Support** *(Expanded in BWT 3.0)*
- **89+ Languages Supported**: *(vs original basic English support)*
- **Complete Translations**: UI, help texts, error messages fully localized
- **Regional Variants**: Specific localizations (en-US, en-GB, es-ES, es-US, etc.)
- **RTL Support**: Right-to-left languages fully supported
- **Cultural Adaptation**: Culturally appropriate layouts and behaviors

---

### 🔧 **Technical Implementation**

#### ⚡ **Performance Optimized**
- **Minimal Permissions**: Only **VIBRATE** permission required
- **No Internet Access**: All cryptographic operations local
- **No External Storage**: No sensitive permission requirements
- **Battery Optimized**: Minimal background processing
- **Hardware Acceleration**: Where available

#### 🏗️ **Modern Architecture** *(Updated in BWT 3.0)*
- **Signal Protocol v3**: Latest cryptographic implementations
- **libsignal-android 0.73.2**: *(vs original older version)* Latest with PQC support
- **Bouncy Castle PQC 1.78.1**: *(New)* Industry-standard post-quantum algorithms
- **Android Security Crypto**: *(New)* Modern encrypted storage
- **Jackson Databind 2.14.1**: Efficient JSON serialization

#### 📦 **Dependencies**
```gradle
implementation 'org.signal:libsignal-android:0.73.2'        // Latest Signal Protocol
implementation 'org.bouncycastle:bcprov-ext-jdk18on:1.78.1' // PQC Support
implementation 'androidx.security:security-crypto:1.1.0'     // Encrypted Storage
implementation 'com.fasterxml.jackson.core:jackson-databind:2.14.1' // JSON
```

---

### 🚀 **Installation & Setup**

#### 📋 **Requirements**
- **Android 8.0 (API 26)** or higher *(same as original)*
- **ARMv7, ARM64, or x86_64** architecture
- **50MB** free storage space
- **No special permissions** required (only VIBRATE)

#### ⚙️ **Initialization Process**
1. **Install APK** or build from source
2. **Enable keyboard** in Android Settings → Language & Input
3. **Set as default** input method
4. **Auto-initialization**: Signal Protocol automatically initializes:
   - Randomized **SignalProtocolAddress** (UUID + device ID)
   - **Identity Key** (permanent, never rotated)
   - **2 One-time PreKeys** *(vs Signal's 100)*
   - **Signed PreKey** (rotates every 2 days)
   - **Kyber PreKeys** *(New in BWT 3.0)*

---

### 🔄 **Usage Workflow**

#### 👥 **Starting Secure Conversations**
1. **Generate Invite**: Create **PreKeyResponse** with ECC + Kyber keys
2. **Share Invite**: Send via any messenger (raw or fairy tale mode)
3. **Contact Import**: Recipient imports from received invite
4. **Session Establishment**: Automatic on first message exchange
5. **Verify Identity**: Compare SHA-512 fingerprints for security

#### 🔐 **Message Operations**
- **Encrypt**: Compose → Select contact → Encrypt → Share via any messenger
- **Decrypt**: Copy encrypted message → Auto-detect → Decrypt → View plaintext
- **History**: *(Enhanced)* View past conversations with deletion option
- **Steganography**: Toggle between raw JSON and fairy tale modes

---

### 🔐 **Security Considerations**

#### ✅ **Security Guarantees**
- **Post-Quantum Resistant**: *(New)* Protection against future quantum computers
- **Perfect Forward Secrecy**: Past messages secure if keys compromised
- **Server-Free Architecture**: No central point of failure
- **Deniable Authentication**: Cannot prove message authorship
- **Enhanced Rotation**: *(Improved)* 2-day key rotation vs 30-day original

#### ⚠️ **Known Limitations**
- **1-to-1 Conversations**: Designed for individual chats primarily
- **Group Chat Limitations**: Limited group functionality
- **Messenger Compatibility**: Some messengers may not handle invisible Unicode properly
- **Message Size Limits**: Some platforms limit message size (3500 bytes)
- **Telegram HTML Issues**: Fairy tale mode may have issues with HTML copying

---

### 🛠️ **Development & Building**

#### 🏗️ **Build Instructions**
```bash
git clone https://github.com/your-repo/SecureChatKeyboardBWT3.0.git
cd SecureChatKeyboardBWT3.0
./gradlew assembleDebug
```

#### 🧪 **Testing**
```bash
./gradlew test                    # Unit tests
./gradlew connectedAndroidTest    # Integration tests
```

#### 📦 **F-Droid Compatible**
- **Reproducible builds** for transparent distribution
- **GPL-3.0 License** maintained from original
- **No proprietary dependencies**
- **Privacy-focused** distribution model

---

### 📚 **Used Libraries & Credits**

#### 📖 **Core Libraries**
- **[Signal Protocol (Android)](https://github.com/signalapp/libsignal)**: E2EE implementation
- **[Jackson](https://github.com/FasterXML/jackson)**: JSON serialization
- **[Protobuf (lite)](https://developers.google.com/protocol-buffers)**: Data serialization
- **[JUnit4](https://junit.org/junit4/)**: Testing framework
- **[Bouncy Castle PQC](https://www.bouncycastle.org/)**: *(New)* Post-quantum cryptography

#### 🙏 **Original Credits**
- **[AOSP Keyboard](https://android.googlesource.com/platform/packages/inputmethods/LatinIME/)**: Base keyboard implementation
- **[Simple Keyboard](https://github.com/rkkr/simple-keyboard)**: UI foundation
- **[OpenBoard](https://github.com/openboard-team/openboard)**: Additional features
- **[FlorisBoard](https://github.com/florisboard/florisboard)**: Modern keyboard concepts

---

---

## Español
<div align="center">
  <img src="https://github.com/user-attachments/assets/5a517fa3-29bd-453f-9242-65a7aa058c79" alt="icono" width="600" />
</div>


<img width="1551" alt="Captura de pantalla 2025-06-09 a las 17 40 52" src="https://github.com/user-attachments/assets/9d02e271-65fb-44da-92c9-a505952da667" />


<img width="1555" alt="Captura de pantalla 2025-06-09 a las 17 40 24" src="https://github.com/user-attachments/assets/f5039166-b0dd-4614-ac60-caa412e3d123" />

<img width="1555" alt="Captura de pantalla 2025-06-09 a las 17 39 49" src="https://github.com/user-attachments/assets/80f09300-9157-4e9d-a229-7c6ed0efeec1" />

### 🌟 Teclado Seguro Post-Cuántico Avanzado para Android

**SecureChats Keyboard BWT 2.0.0** es una versión mejorada del innovador teclado KryptEY para Android, originalmente creado por **mellitopia** y **amnesica**. Esta iteración avanzada integra **cifrado de extremo a extremo (E2EE)** con resistencia a **criptografía post-cuántica**, construido sobre la base del Protocolo Signal con implementación mejorada de **Kyber (PQC)** para seguridad a prueba de futuro contra ataques de computadoras cuánticas.

**🚀 Novedades en BWT 2.0.0:**
- **Criptografía Post-Cuántica (Kyber)** integrada
- **EncryptedSharedPreferences** con AES256-GCM
- **Rotación de claves mejorada** (2 días vs 30 días originales)
- **Eliminación de historial por contacto**
- **89+ localizaciones de idiomas** (vs soporte básico original)
- **libsignal-android 0.73.2** con las últimas mejoras de seguridad

---

### 🔮 **Características de Criptografía Post-Cuántica (PQC)**

#### 🛡️ **Integración de Kyber** *(Nuevo en BWT 3.0)*
- **Cifrado Híbrido**: ECC (Protocolo Signal) + algoritmos resistentes **Kyber Post-Cuántico**
- **Encapsulación KEM**: Mecanismo de Encapsulación de Claves usando proveedor Bouncy Castle PQC  
- **Rotación Automática de Claves**: Las pre-claves Kyber se rotan automáticamente cada 2 días
- **Seguridad a Prueba de Futuro**: Protección contra ataques de computadoras cuánticas (algoritmo de Shor)
- **Sistema Dual de Pre-Claves**: Gestión simultánea de pre-claves ECC y Kyber

#### 🔄 **Gestión de Claves Mejorada** *(Mejorado en BWT 3.0)*
- **Rotación Más Rápida**: Las pre-claves rotan cada **2 días** (vs 30 días originales)
- **Lógica de Rotación Inteligente**: Horarios de rotación independientes para claves ECC y PQC
- **Eliminación Segura**: Claves antiguas purgadas automáticamente después del uso
- **Migración Perfecta**: Compatibilidad hacia atrás con dispositivos KryptEY originales

---

### 🔒 **Arquitectura de Seguridad Mejorada**

#### 📱 **Sistema de Almacenamiento Cifrado** *(Nuevo en BWT 3.0)*
- **EncryptedSharedPreferences**: Todos los datos de usuario cifrados en reposo usando AES256-GCM *(vs SharedPreferences plano original)*
- **Protección de MasterKey**: Keystores respaldados por hardware donde esté disponible
- **Cifrado JSON**: Historial de mensajes, contactos y claves almacenados cifrados
- **Diseño de Conocimiento Cero**: No se almacenan datos en texto plano en el dispositivo

#### 🛡️ **Implementación del Protocolo Signal**
- **Protocolo X3DH**: Curva elíptica X25519 con SHA-512
- **Algoritmo de Doble Ratchet**: Derivación avanzada de claves y autenticación de mensajes
- **AES-256 con CBC (PKCS#7)**: Estándar de cifrado de mensajes
- **SHA-256**: Función hash para varias cadenas
- **SHA-512**: Generación de huella dactilar para representación de clave pública
- **Secreto Perfecto hacia Adelante**: Cada mensaje usa claves de cifrado únicas

#### 🔧 **Gestión de Almacenes del Protocolo**
Toda la información del protocolo almacenada en almacenes especializados:
- **IdentityKeyStore**: Gestión de claves de identidad
- **PreKeyMetadataStore**: Metadatos de pre-claves y horarios de rotación
- **PreKeyStore**: Pre-claves de un solo uso (2 claves vs 100 de Signal)
- **SignedPreKeyStore**: Gestión de pre-claves firmadas
- **SessionStore**: Gestión de estado de sesión
- **SenderKeyStore**: Claves de mensajería grupal
- **SignalProtocolStore**: Interfaz unificada del protocolo
- **BCKyberPreKeyStore**: *(Nuevo)* Pre-claves Kyber post-cuánticas

---

### 📨 **Tipos de Mensajes y Protocolo**

#### 🔄 **Cuatro Tipos de Mensajes**
1. **PreKeyResponse**: Enviar PreKeyBundle (mensaje de invitación)
2. **PreKeySignalMessage**: Enviar texto cifrado + PreKeyBundle después del establecimiento de sesión
3. **SignalMessage**: Enviar texto cifrado regular
4. **PreKeyResponse + SignalMessage**: *(Mejorado)* Enviar texto cifrado con PreKeyBundle actualizado + claves Kyber

#### 📦 **Estructura MessageEnvelope**
Toda la información del mensaje recopilada en un **MessageEnvelope** que contiene:
- **PreKeyResponse**: Datos del paquete de claves (ECC + Kyber en BWT 3.0)
- **CiphertextMessage**: Mensaje cifrado como array de bytes
- **CiphertextType**: Identificador del tipo de mensaje
- **Timestamp**: Hora de creación del mensaje
- **SignalProtocolAddress**: Identificación del remitente (UUID aleatorizado)

---

### 🎭 **Esteganografía y Codificación**

#### 🔤 **Dos Modos de Codificación**
- **Modo Crudo**: Visualización directa de JSON con formato minificado
- **Modo Cuento de Hadas**: Mensajes ocultos en caracteres Unicode invisibles

#### 🧙‍♂️ **Detalles Técnicos del Modo Cuento de Hadas**
- **Caracteres Unicode Invisibles**: 16 characters (U+200C, etc.) for 4-bit mapping
- **Minificación JSON**: Claves abreviadas ("preKeyResponse" → "pR")
- **Compresión GZIP**: Optimización de tamaño antes de la codificación
- **Conversión Binaria**: 4 bits mapeados a Unicode invisible (0000-1111)
- **Historias Señuelo**: Oculto en cuentos de Cenicienta o Rapunzel
- **Reversibilidad Completa**: Extraer → Convertir → Descomprimir → Desminificar

---

### ✨ **Características Avanzadas**

#### 💬 **Mensajería Segura**
- **Cifrado de Extremo a Extremo**: Todos los mensajes cifrados antes de salir del dispositivo
- **Operación Sin Servidor**: Sin servidor central para intercambio de claves *(A diferencia de la app Signal)*
- **Identificación UUID**: UUIDs aleatorizados en lugar de números de teléfono
- **Cifrado en Tiempo Real**: Cifrado/descifrado en vivo mientras escribes

#### 🗑️ **Controles de Privacidad** *(Mejorado en BWT 3.0)*
- **Eliminación de Historial por Contacto**: *(Nuevo)* Eliminar historial de mensajes por contacto con un toque
- **Borrado Criptográfico**: *(Nuevo)* La eliminación segura asegura irrecuperabilidad de datos
- **Gestión de Contactos**: Agregar/eliminar contactos con verificación
- **Gestión de Sesiones**: Establecimiento seguro de sesiones sin servidores

#### 🔧 **Flujo de Establecimiento de Sesión**
1. **Alicia** genera y envía **PreKeyBundle** (mensaje de invitación)
2. **Bob** agrega a Alicia como contacto, establece sesión localmente
3. **Bob** envía **PreKeySignalMessage** (primer mensaje cifrado)
4. **Alicia** agrega a Bob, establece sesión, descifra mensaje
5. Ambas partes intercambian **SignalMessages** para conversación continua
6. **Rotación de Claves**: *(Mejorado)* Cada 2 días con actualizaciones automáticas de PreKeyBundle

---

### 🌍 **Internacionalización**

#### 🗣️ **Soporte Masivo de Idiomas** *(Expandido en BWT 3.0)*
- **89+ Idiomas Soportados**: *(vs soporte básico en inglés original)*
- **Traducciones Completas**: UI, textos de ayuda y mensajes de error totalmente localizados
- **Variantes Regionales**: Localizaciones específicas (en-US, en-GB, es-ES, es-US, etc.)
- **Soporte RTL**: Idiomas de derecha a izquierda totalmente soportados
- **Adaptación Cultural**: Distribuciones y comportamientos culturalmente apropiados

---

### 🔧 **Implementación Técnica**

#### ⚡ **Optimizado para Rendimiento**
- **Permisos Mínimos**: Solo se requiere permiso **VIBRATE**
- **Sin Acceso a Internet**: Todas las operaciones criptográficas locales
- **Sin Almacenamiento Externo**: Sin requisitos de permisos sensibles
- **Optimizado para Batería**: Procesamiento mínimo en segundo plano
- **Aceleración por Hardware**: Donde esté disponible

#### 🏗️ **Arquitectura Moderna** *(Actualizada en BWT 3.0)*
- **Protocolo Signal v3**: Últimas implementaciones criptográficas
- **libsignal-android 0.73.2**: *(vs versión anterior original)* Última con soporte PQC
- **Bouncy Castle PQC 1.78.1**: *(Nuevo)* Algoritmos post-cuánticos estándar de la industria
- **Android Security Crypto**: *(Nuevo)* Almacenamiento cifrado moderno
- **Jackson Databind 2.14.1**: Serialización JSON eficiente

---

### 🚀 **Instalación y Configuración**

#### 📋 **Requisitos**
- **Android 8.0 (API 26)** o superior *(igual que el original)*
- **Arquitectura ARMv7, ARM64 o x86_64**
- **50MB** de espacio libre de almacenamiento
- **Sin permisos especiales** requeridos (solo VIBRATE)

#### ⚙️ **Proceso de Inicialización**
1. **Instalar APK** o compilar desde código fuente
2. **Habilitar teclado** en Configuración de Android → Idioma y Entrada
3. **Establecer como predeterminado** método de entrada
4. **Auto-inicialización**: El Protocolo Signal se inicializa automáticamente:
   - **SignalProtocolAddress** aleatorizado (UUID + ID de dispositivo)
   - **Clave de Identidad** (permanente, nunca rotada)
   - **2 Pre-Claves de Un Uso** *(vs 100 de Signal)*
   - **Pre-Clave Firmada** (rota cada 2 días)
   - **Pre-Claves Kyber** *(Nuevo en BWT 3.0)*

---

### 🔐 **Consideraciones de Seguridad**

#### ✅ **Garantías de Seguridad**
- **Resistente Post-Cuántico**: *(Nuevo)* Protección contra futuras computadoras cuánticas
- **Secreto Perfecto hacia Adelante**: Mensajes pasados seguros si las claves se comprometen
- **Arquitectura Sin Servidor**: Sin punto central de falla
- **Autenticación Negable**: No se puede probar autoría de mensajes
- **Rotación Mejorada**: *(Mejorado)* Rotación de claves de 2 días vs 30 días originales

#### ⚠️ **Limitaciones Conocidas**
- **Conversaciones 1-a-1**: Diseñado principalmente para chats individuales
- **Limitaciones de Chat Grupal**: Funcionalidad grupal limitada
- **Compatibilidad de Mensajeros**: Algunos mensajeros pueden no manejar Unicode invisible correctamente
- **Límites de Tamaño de Mensaje**: Algunas plataformas limitan el tamaño del mensaje (3500 bytes)
- **Problemas HTML de Telegram**: El modo cuento de hadas puede tener problemas con el copiado HTML

---

### 📄 **Licencia**

Licenciado bajo la **Licencia GPL-3.0** (mantenida del original). Ver [LICENSE](LICENSE) para detalles.

---

### 🤝 **Contribuyendo**

¡Las contribuciones son bienvenidas! Por favor lee nuestras [Guías de Contribución](CONTRIBUTING.md) antes de enviar pull requests.

---

### 🔗 **Enlaces Útiles**

- 📋 **Issues**: [GitHub Issues](https://github.com/your-repo/SecureChatKeyboardBWT3.0/issues)
- 📖 **Documentación**: [Wiki](https://github.com/your-repo/SecureChatKeyboardBWT3.0/wiki)
- 💬 **Soporte**: [Discussions](https://github.com/your-repo/SecureChatKeyboardBWT3.0/discussions)
- 🔐 **Auditorías de Seguridad**: [Security Audits](docs/security-audits.md)
- 🎯 **KryptEY Original**: [Proyecto Base](https://github.com/amnesica/KryptEY)

---

**⚡ SecureChats Keyboard BWT 2.0.0 - El Futuro de la Comunicación Móvil Segura ⚡**

*Construido sobre la base sólida de KryptEY con mejoras revolucionarias de seguridad post-cuántica*
