/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.keyczar;

import com.google.gson.annotations.Expose;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.util.Base64Coder;
import com.google.keyczar.util.Util;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * A wrapper for a public key associated with a X.509 certificate.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
abstract class KeyczarPublicKey extends KeyczarKey {
  private PublicKey jcePublicKey;
  
  @SuppressWarnings("unused") @Expose private KeyType type = getType();
  @Expose String x509;
  
  private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  public PublicKey getJcePublicKey() {
    return jcePublicKey;
  }

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  abstract String getKeyGenAlgorithm();

  @Override
  byte[] hash() {
    return hash;
  }

  void init() throws KeyczarException {
    byte[] x509Bytes = Base64Coder.decode(x509);
    try {
      KeyFactory kf = KeyFactory.getInstance(getKeyGenAlgorithm());
      jcePublicKey = kf.generatePublic(new X509EncodedKeySpec(x509Bytes));
      byte[] fullHash = Util.prefixHash(x509Bytes);
      System.arraycopy(fullHash, 0, hash, 0, hash.length);      
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  void set(byte[] x509Bytes) throws KeyczarException {
    type = getType();
    x509 = Base64Coder.encode(x509Bytes);
    byte[] fullHash = Util.prefixHash(x509Bytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    init();
  }
}
