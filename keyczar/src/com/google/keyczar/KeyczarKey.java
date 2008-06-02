// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.Stream;

import java.nio.ByteBuffer;

import java.util.concurrent.ConcurrentLinkedQueue;

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
  
  abstract Integer hashKey();
  
  @Override
  public abstract int hashCode();

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
}
