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

import com.google.gson.annotations.Expose;

import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

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
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
class HmacKey extends KeyczarKey {
  private static final String MAC_ALGORITHM = "HMACSHA1";

  @Expose private String hmacKeyString;

  private Key hmacKey;
  private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  static HmacKey generate() throws KeyczarException {
    return generate(KeyType.HMAC_SHA1.defaultSize());
  }

  static HmacKey generate(int keySize) throws KeyczarException {
    HmacKey key = new HmacKey();
    key.size = keySize;
    byte[] keyBytes = Util.rand(key.size() / 8);
    key.hmacKeyString = Base64Coder.encode(keyBytes);
    key.init();
    return key;
  }

  void init() throws KeyczarException {
    byte[] keyBytes = Base64Coder.decode(hmacKeyString);
    byte[] fullHash = Util.hash(keyBytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    hmacKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
  }

  /*
   * This method is for AesKey to grab the key bytes to compute an identifying
   * hash.
   */
  byte[] keyBytes() {
    return hmacKey.getEncoded();
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

    public void initSign() throws KeyczarException {
      try {
        hmac.init(hmacKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public void initVerify() throws KeyczarException {
      initSign();
    }

    public void sign(ByteBuffer output) {
      output.put(hmac.doFinal());
    }

    public void updateSign(ByteBuffer input) {
      hmac.update(input);
    }

    public void updateVerify(ByteBuffer input) {
      updateSign(input);
    }

    public boolean verify(ByteBuffer signature) {
      byte[] sigBytes = new byte[signature.remaining()];
      signature.get(sigBytes);

      return Arrays.equals(hmac.doFinal(), sigBytes);
    }
  }
}