### **Resumen de los cambios y mejoras para añadir soporte PQC (Kyber) en tu proyecto**

1. **Incorporación de la librería Bouncy Castle PQC**

    - Se incluyó la dependencia de BouncyCastle con soporte post-cuántico (p.e. `bcprov-ext-jdk15to18-1.72.jar`), la cual expone las clases necesarias para trabajar con el algoritmo Kyber (`KyberParameterSpec`, `KEMGenerateSpec`, `KEMExtractSpec`, etc.).
    - Esto permite generar y manejar claves Kyber, así como realizar la encapsulación/decapsulación KEM.

2. **Creación de utilidades para Kyber**

    - En el paquete `pqc`, se agregaron clases como `KyberUtil.java` para:
        - Generar pares de claves Kyber (`generateKyberKeyPair(...)`).
        - Realizar la encapsulación/decapsulación KEM (`kemEncapsulate(...)` y `kemDecapsulate(...)`).
    - Se siguió un flujo similar a las llaves ECC, pero usando la API de BouncyCastle PQC.

3. **Adaptación de la lógica de PreKeys para incluir Kyber**

    - Se creó un `BCKyberPreKeyRecord` (o clase equivalente) para almacenar la pre-clave Kyber (similar a las “pre-claves ECC”).
    - En `SignalProtocolStoreImpl` se añadió un `BcKyberPreKeyStore`, que maneja la persistencia de estas pre-claves PQC (métodos `storePreKey(...)`, `removePreKey(...)`, etc.).

4. **Rotación automática de las pre-claves Kyber**

    - Se replicó la lógica de rotación de las pre-claves ECC en `KeyUtil`, creando los métodos:
        - `generateAndStoreKyberPreKey(...)`
        - `refreshKyberPreKeyIfNecessary(...)`
        - `deleteOldKyberPreKeysIfNecessary(...)`
    - Estos métodos siguen el mismo patrón de “cada X días” (por defecto, 2) para generar una nueva pre-clave Kyber y eliminar la antigua. Se usan los campos `nextKyberPreKeyRefreshTime` y `oldKyberPreKeyDeletionTime` en `PreKeyMetadataStore`.

5. **Integración en `SignalProtocolMain`**

    - En el método `encrypt(...)`, además de chequear la rotación ECC (`refreshSignedPreKeyIfNecessary(...)`), ahora se llama también a `KeyUtil.refreshKyberPreKeyIfNecessary(...)`.
    - En `initializeProtocol()`, tras la generación de las pre-claves ECC, se llama a `KeyUtil.generateAndStoreKyberPreKey(...)` para iniciar el soporte PQC, y se programan las fechas de rotación y eliminación con las 3 líneas nuevas (solo si se desea la misma granularidad que ECC):
      ```java
      long now = System.currentTimeMillis();
      metadataStore.setNextKyberPreKeyRefreshTime(now + KeyUtil.getSignedPreKeyMaxDays());
      metadataStore.setOldKyberPreKeyDeletionTime(now + KeyUtil.getSignedPreKeyArchiveAge());
      ```
    - En la recepción de un `PreKeyResponse`, si vienen campos de Kyber (`kyberPubKey` y `kyberPreKeyId`), se realiza la lógica de encapsulación KEM para cifrar una clave AES de forma post-cuántica.

6. **Cambios en la serialización de `PreKeyResponse`**

    - Se añadieron dos campos nuevos en `PreKeyResponse`: `byte[] kyberPubKey` y `int kyberPreKeyId`, para enviar/recibir la pre-clave Kyber en el intercambio inicial.
    - Se expandió el método `createPreKeyResponseMessage()` para adjuntar la pre-clave Kyber pública al `PreKeyResponse`, y luego crear el `MessageEnvelope`.

7. **Estructuras de almacenamiento y metadatos**

    - En `PreKeyMetadataStore` se agregaron los campos:
        - `long nextKyberPreKeyRefreshTime`
        - `long oldKyberPreKeyDeletionTime`
    - Estos se guardan junto con los demás metadatos en la persistencia (almacenamiento local o `SharedPreferences`).
    - Se actualizó la capa de persistencia (`StorageHelper`, etc.) para contemplar dichos nuevos campos.

8. **Resultado final**

   Ahora, el proyecto cuenta con un cifrado híbrido **ECC + PQC**:
    - ECC (tipo Signal clásico) para la parte del handshake y derivación de sesión.
    - Kyber para una segunda capa de protección (generación o intercambio de una clave simétrica AES de forma post-cuántica), con su propia rotación y eliminación de pre-claves antiguas.
    - Se garantiza que en cada mensaje se revisa si se cumplió el tiempo de rotación tanto para ECC (SignedPreKey) como para PQC (KyberPreKey), y se generan/borran dichas pre-claves automáticamente, manteniendo siempre un estado seguro de las mismas.


 ## ARCHIVOS MODIFICADOS:
'''BCKyberPreKeyRecord.java
BCKyberPreKeyStoreImpl.java
build.gradle
KeyUtil.java
KyberUtil.java
PQCKeyFactoryHelper.java
PreKeyMetadataStore.java
PreKeyMetadataStoreImpl.java
PreKeyResponse.java
SignalProtocolMain.java
SignalProtocolStoreImpl.java'''
