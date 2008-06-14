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
import com.google.keyczar.interfaces.SigningStream;
import com.google.keyczar.interfaces.Stream;
import com.google.keyczar.interfaces.VerifyingStream;
import com.google.keyczar.util.Base64Coder;
import com.google.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/**
 * Wrapping class for HMAC-SHA1 keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 * 
 */
class HmacKey extends KeyczarKey {
  private Key hmacKey;
  private static final String MAC_ALGORITHM = "HMACSHA1";
  
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private String hmacKeyString;
  @Expose private KeyType type = KeyType.HMAC_SHA1;

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }
  
  @Override
  public int hashCode() {
    return (hash[0] << 24) | hash[1] << 16 | hash[2] << 8 | hash[3];
  }

  static HmacKey generate() throws KeyczarException {
    HmacKey key = new HmacKey();
    byte[] keyBytes = Util.rand(key.getType().defaultSize() / 8);
    key.hmacKeyString = Base64Coder.encode(keyBytes);
    byte[] fullHash = Util.prefixHash(keyBytes);
    System.arraycopy(fullHash, 0, key.hash, 0, key.hash.length);
    key.init();
    return key;
  }
  
  void init() throws KeyczarException {
    byte[] keyBytes = Base64Coder.decode(hmacKeyString);
    byte[] fullHash = Util.prefixHash(keyBytes);
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Hash does not match");
      }
    }
    hmacKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new HmacStream();
  }

  @Override
  KeyType getType() {
    return KeyType.HMAC_SHA1;
  }

  @Override
  byte[] hash() {
    return hash;
  }

  static HmacKey read(String input) throws KeyczarException {
    HmacKey key = Util.gson().fromJson(input, HmacKey.class);
    if (key.getType() != KeyType.HMAC_SHA1) {
      throw new KeyczarException("Invalid type in input: " + key.getType());
    }
    key.init();
    return key;
  }

  private class HmacStream implements VerifyingStream, SigningStream {
    private Mac hmac;

    public HmacStream() throws KeyczarException {
      try {
        hmac = Mac.getInstance(MAC_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
    }

    @Override
    public void initSign() throws KeyczarException {
      try {
        hmac.init(hmacKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify() throws KeyczarException {
      initSign();
    }

    @Override
    public void sign(ByteBuffer output) {
      output.put(hmac.doFinal());
    }

    @Override
    public void updateSign(ByteBuffer input) {
      hmac.update(input);
    }

    @Override
    public void updateVerify(ByteBuffer input) {
      updateSign(input);
    }

    @Override
    public boolean verify(ByteBuffer signature) {
      byte[] sigBytes = new byte[digestSize()];
      signature.get(sigBytes);

      return Arrays.equals(hmac.doFinal(), sigBytes);
    }
  }
}
