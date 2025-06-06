package com.bwt.securechats.inputmethod.signalprotocol.prekey;

import com.bwt.securechats.inputmethod.signalprotocol.util.Base64;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

import java.io.IOException;
import java.util.Objects;

@JsonFormat(shape = JsonFormat.Shape.ARRAY)
public class PreKeyEntity {

  @JsonProperty
  private int keyId;

  @JsonProperty
  @JsonSerialize(using = ECPublicKeySerializer.class)
  @JsonDeserialize(using = ECPublicKeyDeserializer.class)
  private ECPublicKey publicKey;

  public PreKeyEntity() {
  }

  public PreKeyEntity(int keyId, ECPublicKey publicKey) {
    this.keyId = keyId;
    this.publicKey = publicKey;
  }

  public int getKeyId() {
    return keyId;
  }

  public ECPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    PreKeyEntity that = (PreKeyEntity) o;
    return keyId == that.keyId && Objects.equals(publicKey, that.publicKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(keyId, publicKey);
  }

  private static class ECPublicKeySerializer extends JsonSerializer<ECPublicKey> {
    @Override
    public void serialize(ECPublicKey value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
      gen.writeString(Base64.encodeBytesWithoutPadding(value.serialize()));
    }
  }

  private static class ECPublicKeyDeserializer extends JsonDeserializer<ECPublicKey> {
    @Override
    public ECPublicKey deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
      try {
        return Curve.decodePoint(Base64.decodeWithoutPadding(p.getValueAsString()), 0);
      } catch (InvalidKeyException e) {
        throw new IOException(e);
      }
    }
  }
}
