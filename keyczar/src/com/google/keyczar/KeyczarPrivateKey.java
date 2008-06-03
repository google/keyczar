// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.gson.annotations.Expose;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.util.Base64Coder;
import com.google.keyczar.util.Util;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;


abstract class KeyczarPrivateKey extends KeyczarKey {
  private PrivateKey jcePrivateKey;
  private Integer hashCodeObject;
  private int hashCode;
  
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private String pkcs8;
  @Expose private KeyType type = getType();

  @Override
  public Integer hashKey() {
    return hashCodeObject;
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
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(getKeyGenAlgorithm());
      kpg.initialize(getType().defaultSize());
      KeyPair pair = kpg.generateKeyPair();
      jcePrivateKey = pair.getPrivate();
      getPublic().set(pair.getPublic().getEncoded());
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
    hash = getPublic().hash();
    pkcs8 = Base64Coder.encode(jcePrivateKey.getEncoded());
    init();
  }

  PrivateKey getJcePrivateKey() {
    return jcePrivateKey;
  }

  abstract String getKeyGenAlgorithm();

  abstract KeyczarPublicKey getPublic();

  @Override
  byte[] hash() {
    return hash;
  }

  void init() throws KeyczarException {
    hashCode = Util.toInt(hash);
    hashCodeObject = new Integer(hashCode);
    byte[] pkcs8Bytes = Base64Coder.decode(pkcs8);
    try {
      KeyFactory kf = KeyFactory.getInstance(getKeyGenAlgorithm());
      jcePrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  @Override
  void read(String input) throws KeyczarException {
    KeyczarPrivateKey copy = Util.gson().fromJson(input, this.getClass());
    if (copy.type != getType()) {
      throw new KeyczarException("Incorrect type. Received: " + copy.type
          + " Expected: " + getType());
    }
    type = copy.type;
    hash = copy.hash;
    pkcs8 = copy.pkcs8;
    setPublic(copy.getPublic());
    if (!Arrays.equals(hash, getPublic().hash())) {
      throw new KeyczarException("Key hash does not match");
    }
    init();
  }

  abstract void setPublic(KeyczarPublicKey pub) throws KeyczarException;
}
