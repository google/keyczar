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

import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyType;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.keyparams.KeyParameters;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Wrapping class for HMAC-SHA1 keys
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public class HmacKey extends KeyczarKey {
  private static final String MAC_ALGORITHM = "HMACSHA1";
  private static final int HMAC_DIGEST_SIZE = 20;

  private final String hmacKeyString;

  private SecretKey hmacKey;
  private final byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  public HmacKey(byte[] keyBytes) throws KeyczarException {
    super(keyBytes.length * 8);
    hmacKeyString = Base64Coder.encodeWebSafe(keyBytes);
    initJceKey(keyBytes);
  }

  private HmacKey(int size, String hmacKeyString) {
    super(size);
    this.hmacKeyString = hmacKeyString;
  }

  static HmacKey generate(KeyParameters params) throws KeyczarException {
    return new HmacKey(Util.rand(params.getKeySize() / 8));
  }

  void initFromJson() throws KeyczarException {
    initJceKey(Base64Coder.decodeWebSafe(hmacKeyString));
  }

  private void initJceKey(byte[] keyBytes) throws KeyczarException {
    hmacKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
    System.arraycopy(Util.hash(keyBytes), 0, hash, 0, hash.length);
  }

  /*
   * This method is for AesKey to grab the key bytes to compute an identifying
   * hash.
   */
  byte[] getEncoded() {
    return hmacKey.getEncoded();
  }

  @Override
  protected Stream getStream() throws KeyczarException {
    Stream cachedStream = cachedStreams.poll();
    if (cachedStream != null) {
      return cachedStream;
    } 
    return new HmacStream();
  }

  @Override
  public KeyType getType() {
    return DefaultKeyType.HMAC_SHA1;
  }

  @Override
  protected byte[] hash() {
    return hash;
  }

  static HmacKey read(String input) throws KeyczarException {
    try {
      HmacKey key = fromJson(new JSONObject(input));
      key.initFromJson();
      return key;
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  static HmacKey fromJson(JSONObject json) throws JSONException {
    return new HmacKey(
        json.getInt("size"),
        json.getString("hmacKeyString"));
  }

  @Override
  JSONObject toJson() {
    try {
      return new JSONObject()
        .put("size", size)
        .put("hmacKeyString", hmacKeyString);
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected SecretKey getJceKey() {
    return hmacKey;
  }

  private class HmacStream implements VerifyingStream, SigningStream {
    private final Mac hmac;

    public HmacStream() throws KeyczarException {
      try {
        hmac = Mac.getInstance(MAC_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int digestSize() {
      return HMAC_DIGEST_SIZE;
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
      byte[] sigBytes = new byte[signature.remaining()];
      signature.get(sigBytes);

      return Util.safeArrayEquals(hmac.doFinal(), sigBytes);
    }
  }
}
