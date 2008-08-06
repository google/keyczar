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

package org.keyczar;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import com.google.gson.annotations.Expose;

/**
 * A wrapper for a private key paired asymmetrically with a public key.
 * Encodes info using PCKS #8 standard.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
abstract class KeyczarPrivateKey extends KeyczarKey {
  protected PrivateKey jcePrivateKey;
  
  @Expose protected String pkcs8;
  
  protected byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  PrivateKey getJcePrivateKey() {
    return jcePrivateKey;
  }

  abstract String getKeyGenAlgorithm();

  /**
   * Get the public key paired with this private key.
   * 
   * @return KeyczarPublicKey associated with this KeyczarPrivateKey
   */
  abstract KeyczarPublicKey getPublic();

  @Override
  byte[] hash() {
    return hash;
  }

  void init() throws KeyczarException {
    byte[] pkcs8Bytes = Base64Coder.decode(pkcs8);
    try {
      KeyFactory kf = KeyFactory.getInstance(getKeyGenAlgorithm());
      jcePrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
      getPublic().init();
      hash = getPublic().hash();
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  abstract void setPublic(KeyczarPublicKey pub) throws KeyczarException;
}
