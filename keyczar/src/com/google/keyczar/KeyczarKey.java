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

  abstract Stream getStream() throws KeyczarException;

  abstract KeyType getType();

  /**
   * Return this key's hash value
   * 
   * @return A hash of this key material
   */
  abstract byte[] hash();

  static KeyczarKey genKey(KeyType type) throws KeyczarException {
    switch (type) {
    case AES:
      return AesKey.generate();
    case HMAC_SHA1:
      return HmacKey.generate();
    case DSA_PRIV:
      return DsaPrivateKey.generate();
    case RSA_PRIV:
      return RsaPrivateKey.generate();
    case RSA_PUB: case DSA_PUB:
      throw new KeyczarException("Public keys of type " + type +
          " must be exported from private keys");
    }

    throw new KeyczarException("Unsupported key type: " + type);
  }
  
  static KeyczarKey readKey(KeyType type, String key) throws KeyczarException {
    switch (type) {
    case AES:
      return AesKey.read(key);
    case HMAC_SHA1:
      return HmacKey.read(key);
    case DSA_PRIV:
      return DsaPrivateKey.read(key);
    case DSA_PUB:
      return DsaPublicKey.read(key);
    case RSA_PRIV:
      return RsaPrivateKey.read(key);
    case RSA_PUB:
      return RsaPublicKey.read(key);
    }

    throw new KeyczarException("Unsupported key type: " + type);
  }
}
