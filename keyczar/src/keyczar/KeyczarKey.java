package keyczar;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import keyczar.internal.Constants;
import keyczar.internal.Util;

abstract class KeyczarKey {
  static KeyczarKey fromType(KeyType type) throws KeyczarException {
    switch(type) {
      case AES:
        return new AesKey();
      case HMAC_SHA1:
        return new HmacKey();
      case DSA_PRIV:
        return new DsaPrivateKey();
    }
    
    throw new KeyczarException("Unsupported key type: " + type);
  }
  
  void copyHeader(ByteBuffer dest) {
    dest.put(Constants.VERSION);
    dest.put(this.hash());
  }
  
  /**
   * Return this key's hash value
   *
   * @return A hash of this key material
   */
  protected abstract byte[] hash();

  protected abstract KeyType getType();
   
  protected abstract void read(String input) throws KeyczarException;

  protected abstract void generate() throws KeyczarException;
  
  protected abstract Stream getStream() throws KeyczarException;
  
  protected abstract static class Stream {
  }
}
