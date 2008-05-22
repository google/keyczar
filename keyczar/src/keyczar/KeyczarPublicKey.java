package keyczar;

import com.google.gson.annotations.Expose;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import keyczar.enums.KeyType;


abstract class KeyczarPublicKey extends KeyczarKey {
  private int hashCode;
  private PublicKey jcePublicKey;
  
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private KeyType type = getType();
  @Expose private String x509;

  public PublicKey getJcePublicKey() {
    return jcePublicKey;
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  @Override
  void generate() throws KeyczarException {
    throw new KeyczarException("Keyczar public keys must be exported "
        + "from private keys");
  }

  abstract String getKeyGenAlgorithm();

  @Override
  byte[] hash() {
    return hash;
  }

  void init() throws KeyczarException {
    hashCode = Util.toInt(hash);
    byte[] x509Bytes = Util.base64Decode(x509);
    try {
      KeyFactory kf = KeyFactory.getInstance(getKeyGenAlgorithm());
      jcePublicKey = kf.generatePublic(new X509EncodedKeySpec(x509Bytes));
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  @Override
  void read(String input) throws KeyczarException {
    KeyczarPublicKey copy = Util.gson().fromJson(input, this.getClass());
    if (copy.type != getType()) {
      throw new KeyczarException("Incorrect type. Received: " + copy.type
          + " Expected: " + getType());
    }
    type = copy.type;
    hash = copy.hash;
    x509 = copy.x509;
    byte[] fullHash = Util.prefixHash(Util.base64Decode(x509));
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Key hash does not match");
      }
    }
    init();
  }

  void set(byte[] x509Bytes) throws KeyczarException {
    type = getType();
    x509 = Util.base64Encode(x509Bytes);
    byte[] fullHash = Util.prefixHash(x509Bytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    init();
  }
}
