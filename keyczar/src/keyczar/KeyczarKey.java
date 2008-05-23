package keyczar;

import java.nio.ByteBuffer;

import keyczar.enums.KeyType;

abstract class KeyczarKey {
  void copyHeader(ByteBuffer dest) {
    dest.put(Keyczar.VERSION);
    dest.put(hash());
  }

  abstract void generate() throws KeyczarException;

  abstract Stream getStream() throws KeyczarException;

  abstract KeyType getType();

  /**
   * Return this key's hash value
   * 
   * @return A hash of this key material
   */
  abstract byte[] hash();

  abstract void read(String input) throws KeyczarException;

  static KeyczarKey fromType(KeyType type) throws KeyczarException {
    switch (type) {
    case AES:
      return new AesKey();
    case HMAC_SHA1:
      return new HmacKey();
    case DSA_PRIV:
      return new DsaPrivateKey();
    case DSA_PUB:
      return new DsaPublicKey();
    case RSA_PRIV:
      return new RsaPrivateKey();
    case RSA_PUB:
      return new RsaPublicKey();
    }

    throw new KeyczarException("Unsupported key type: " + type);
  }

  abstract static class Stream {
  }
}
