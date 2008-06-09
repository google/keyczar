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
import com.google.keyczar.enums.CipherMode;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.exceptions.ShortBufferException;
import com.google.keyczar.interfaces.DecryptingStream;
import com.google.keyczar.interfaces.EncryptingStream;
import com.google.keyczar.interfaces.SigningStream;
import com.google.keyczar.interfaces.Stream;
import com.google.keyczar.interfaces.VerifyingStream;
import com.google.keyczar.util.Base64Coder;
import com.google.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Wrapping class for AES keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
class AesKey extends KeyczarKey {
  private Key aesKey;
  private int blockSize;
  private Integer hashCodeObject;
  private int hashCode;
  
  private static final String AES_ALGORITHM = "AES";
  // Default mode is CBC
  private static final CipherMode DEFAULT_MODE = CipherMode.CBC;

  @Expose private String aesKeyString = "";
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private HmacKey hmacKey = new HmacKey();
  @Expose private CipherMode mode = DEFAULT_MODE;
  @Expose private KeyType type = KeyType.AES;

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
    byte[] aesBytes = Util.rand(getType().defaultSize() / 8);
    aesKeyString = Base64Coder.encode(aesBytes);
    mode = DEFAULT_MODE;
    type = getType();
    hmacKey.generate();
    byte[] fullHash = Util.prefixHash(aesBytes, hmacKey.hash());
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new AesStream();
  }

  @Override
  KeyType getType() {
    return KeyType.AES;
  }

  @Override
  byte[] hash() {
    return hash;
  }

  @Override
  void read(String input) throws KeyczarException {
    AesKey copy = Util.gson().fromJson(input, AesKey.class);
    if (copy.type != getType()) {
      throw new KeyczarException("Invalid type in input: " + copy.type);
    }
    hash = copy.hash;
    type = copy.type;
    mode = copy.mode;
    aesKeyString = copy.aesKeyString;
    hmacKey = copy.hmacKey;
    hmacKey.init();

    // Check that the hash is correct
    byte[] aesBytes = Base64Coder.decode(aesKeyString);
    byte[] fullHash = Util.prefixHash(aesBytes, hmacKey.hash());
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Hash does not match");
      }
    }
    init();
  }

  private void init() throws KeyczarException {
    byte[] aesBytes = Base64Coder.decode(aesKeyString);
    hashCode = Util.toInt(hash);
    hashCodeObject = new Integer(hashCode);
    aesKey = new SecretKeySpec(aesBytes, AES_ALGORITHM);
    blockSize = aesBytes.length;
  }

  private class AesStream implements EncryptingStream, DecryptingStream {
    private Cipher encryptingCipher;
    private Cipher decryptingCipher;
    private SigningStream signStream;
    boolean ivRead = false;
    private SecureRandom randomGenerator = new SecureRandom();

    public AesStream() throws KeyczarException  {
      // The JCE Cipher.init() call essentially reallocates a new Cipher object
      // So, we avoid having to reinitialize Ciphers by setting two here here
      // with zero-valued IVs. 
      IvParameterSpec zeroIv = new IvParameterSpec(new byte[blockSize]);
      try {
        encryptingCipher = Cipher.getInstance(mode.getMode());
        encryptingCipher.init(Cipher.ENCRYPT_MODE, aesKey, zeroIv);
        decryptingCipher = Cipher.getInstance(mode.getMode());
        decryptingCipher.init(Cipher.DECRYPT_MODE, aesKey, zeroIv);
        signStream = (SigningStream) hmacKey.getStream();
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
 
    }

    @Override
    public SigningStream getSigningStream() {
      return signStream;
    }

    @Override
    public VerifyingStream getVerifyingStream() {
      return (VerifyingStream) signStream;
    }

    @Override
    public void initDecrypt(ByteBuffer input) {
      // This will simply decrypt the first block, leaving the CBC Cipher
      // ready for the next block of input.
      byte[] iv = new byte[blockSize];
      input.get(iv);
      decryptingCipher.update(iv);
      ivRead = true;
    }

    @Override
    public int initEncrypt(ByteBuffer output) throws KeyczarException {
      // Generate a random value and encrypt it. This will be the IV.
      byte[] ivPreImage = new byte[blockSize];
      randomGenerator.nextBytes(ivPreImage);
      try {
        return encryptingCipher.update(ByteBuffer.wrap(ivPreImage), output);
      } catch (javax.crypto.ShortBufferException e) {
        throw new ShortBufferException(e);
      }
    }

    @Override
    public int updateDecrypt(ByteBuffer input, ByteBuffer output)
    throws KeyczarException {
      if (ivRead) {
        // The next output block will be the IV preimage, which we'll discard
        byte[] temp = new byte[blockSize];
        input.get(temp);
        byte[] ivPreimage = decryptingCipher.update(temp);
        ivRead = false;
      }
      try {
        return decryptingCipher.update(input, output);
      } catch (javax.crypto.ShortBufferException e) {
        throw new ShortBufferException(e);
      }
    }

    @Override
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
    throws KeyczarException {
      try {
        return encryptingCipher.update(input, output);
      } catch (javax.crypto.ShortBufferException e) {
        throw new ShortBufferException(e);
      }
    }

    @Override
    public int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
    throws KeyczarException {
      if (ivRead) {
        // The next output block will be the IV preimage, which we'll discard
        byte[] temp = new byte[blockSize];
        input.get(temp);
        byte[] ivPreimage = decryptingCipher.update(temp);
        ivRead = false;
      }
      try {
        return decryptingCipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
    throws KeyczarException {
      try {
        return encryptingCipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int maxOutputSize(int inputLen) {
      switch (mode) {
      case ECB:
        return blockSize;
      case CTR:
        return inputLen + blockSize / 2;
      case CBC:
      default:
        return (inputLen / blockSize + 2) * blockSize;
      }
    }
  }
}
