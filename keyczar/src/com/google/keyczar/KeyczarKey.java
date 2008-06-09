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

import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.Stream;

import java.nio.ByteBuffer;

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
