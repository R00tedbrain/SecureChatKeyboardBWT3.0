package com.bwt.securechats.inputmethod.signalprotocol.prekey;

import com.bwt.securechats.inputmethod.signalprotocol.util.JsonUtil;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import org.signal.libsignal.protocol.IdentityKey;

import java.util.List;
import java.util.Objects;

/**
 * Modelo que representa la respuesta de pre-claves (ECC + PQC).
 * Incluye IdentityKey, lista de devices ECC y, opcionalmente, la parte Kyber:
 *   - kyberPubKey: la pública PQC (X.509-coded)
 *   - kyberPreKeyId: ID de la pre-clave PQC.
 */
@JsonFormat(shape = JsonFormat.Shape.ARRAY)
public class PreKeyResponse {

  @JsonProperty
  @JsonSerialize(using = JsonUtil.IdentityKeySerializer.class)
  @JsonDeserialize(using = JsonUtil.IdentityKeyDeserializer.class)
  private IdentityKey identityKey;

  @JsonProperty
  private List<PreKeyResponseItem> devices;

  // ----------------------------------------------------
  // NUEVOS CAMPOS: PQC (Kyber)
  // ----------------------------------------------------

  /**
   * Clave pública Kyber (codificada en X.509),
   * compartida como parte de la respuesta, para que el contacto la use.
   */
  @JsonProperty
  private byte[] kyberPubKey;

  /**
   * ID de la pre-clave Kyber (paralelo a preKeyId ECC).
   */
  @JsonProperty
  private int kyberPreKeyId;

  /**
   * Firma de la clave pública Kyber (requerida en libsignal 0.73.2).
   */
  @JsonProperty
  private byte[] kyberSignature;

  // ----------------------------------------------------
  // Constructores
  // ----------------------------------------------------

  public PreKeyResponse() {
    // Constructor por defecto (para JSON)
  }

  public PreKeyResponse(IdentityKey identityKey, List<PreKeyResponseItem> devices) {
    this.identityKey = identityKey;
    this.devices = devices;
  }

  // ----------------------------------------------------
  // Getters / Setters
  // ----------------------------------------------------

  public IdentityKey getIdentityKey() {
    return identityKey;
  }

  public void setIdentityKey(IdentityKey identityKey) {
    this.identityKey = identityKey;
  }

  public List<PreKeyResponseItem> getDevices() {
    return devices;
  }

  public void setDevices(List<PreKeyResponseItem> devices) {
    this.devices = devices;
  }

  public byte[] getKyberPubKey() {
    return kyberPubKey;
  }

  public void setKyberPubKey(byte[] kyberPubKey) {
    this.kyberPubKey = kyberPubKey;
  }

  public int getKyberPreKeyId() {
    return kyberPreKeyId;
  }

  public void setKyberPreKeyId(int kyberPreKeyId) {
    this.kyberPreKeyId = kyberPreKeyId;
  }

  public byte[] getKyberSignature() {
    return kyberSignature;
  }

  public void setKyberSignature(byte[] kyberSignature) {
    this.kyberSignature = kyberSignature;
  }

  // ----------------------------------------------------
  // equals, hashCode, toString
  // ----------------------------------------------------

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    PreKeyResponse that = (PreKeyResponse) o;
    return kyberPreKeyId == that.kyberPreKeyId &&
            Objects.equals(identityKey, that.identityKey) &&
            Objects.equals(devices, that.devices) &&
            // Comparamos contenido de arrays PQC:
            (kyberPubKey == null ? (that.kyberPubKey == null)
                    : java.util.Arrays.equals(kyberPubKey, that.kyberPubKey)) &&
            (kyberSignature == null ? (that.kyberSignature == null)
                    : java.util.Arrays.equals(kyberSignature, that.kyberSignature));
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(identityKey, devices, kyberPreKeyId);
    result = 31 * result + (kyberPubKey != null ? java.util.Arrays.hashCode(kyberPubKey) : 0);
    result = 31 * result + (kyberSignature != null ? java.util.Arrays.hashCode(kyberSignature) : 0);
    return result;
  }

  @Override
  public String toString() {
    return "PreKeyResponse{" +
            "identityKey=" + identityKey +
            ", devices=" + devices +
            ", kyberPubKey=" + (kyberPubKey == null ? null : ("len=" + kyberPubKey.length)) +
            ", kyberPreKeyId=" + kyberPreKeyId +
            ", kyberSignature=" + (kyberSignature == null ? null : ("len=" + kyberSignature.length)) +
            '}';
  }
}
