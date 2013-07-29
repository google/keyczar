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

import org.keyczar.enums.CipherMode;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortBufferException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.DecryptingStream;
import org.keyczar.interfaces.EncryptingStream;
import org.keyczar.interfaces.KeyType;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.keyparams.AesKeyParameters;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Wrapping class for AES keys. Currently the default is to use CBC mode.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public class AesKey extends KeyczarKey {
  private static final DefaultKeyType KEY_TYPE = DefaultKeyType.AES;
  private static final int BLOCK_SIZE = 16;
  private static final String AES_ALGORITHM = "AES";
  private static final CipherMode DEFAULT_MODE = CipherMode.CBC;

  private SecretKey aesKey;
  @Expose private final String aesKeyString;
  @Expose private final HmacKey hmacKey;
  @Expose private final CipherMode mode;

  private final byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  /**
   * Creates an AES key from the provided key data and HMAC key.  The key data can be any
   * byte array, but must be a valid AES key length (128, 192 or 256 bits).
   */
  public AesKey(byte[] aesKeyBytes, HmacKey hmacKey) throws KeyczarException {
    super(aesKeyBytes.length * 8);
    this.aesKeyString = Base64Coder.encodeWebSafe(aesKeyBytes);
    this.mode = DEFAULT_MODE;
    this.hmacKey = hmacKey;
    initJceKey(aesKeyBytes);
  }

  // Used by GSON, which will overwrite the values set here.
  private AesKey() {
    super(0);
    aesKeyString = null;
    hmacKey = null;
    mode = null;
  }

  static AesKey generate(AesKeyParameters params) throws KeyczarException {
    return new AesKey(Util.rand(params.getKeySize() / 8), params.getHmacKey());
  }

  /*
   * Used by SessionDecrypters when decrypting encrypted keys
   */
  static AesKey fromPackedKey(byte[] packedKeys) throws KeyczarException {
    byte[][] unpackedKeys = Util.lenPrefixUnpack(packedKeys);
    if (unpackedKeys.length != 2) {
      throw new KeyczarException(Messages.getString("AesKey.InvalidPackedKey"));
    }
    return new AesKey(unpackedKeys[0], new HmacKey(unpackedKeys[1]));
  }

  @Override
  public KeyType getType() {
    return KEY_TYPE;
  }

  @Override
  protected byte[] hash() {
    return hash;
  }

  static AesKey read(String input) throws KeyczarException {
    AesKey key = Util.gson().fromJson(input, AesKey.class);
    key.hmacKey.initFromJson();
    key.initJceKey(Base64Coder.decodeWebSafe(key.aesKeyString));
    return key;
  }

  private void initJceKey(byte[] aesBytes) throws KeyczarException {
    aesKey = new SecretKeySpec(aesBytes, AES_ALGORITHM);
    byte[] fullHash = Util.hash(Util.fromInt(BLOCK_SIZE), aesBytes, hmacKey.getEncoded());
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
  }

  /*
   * Used by SessionEncrypters to get a packed representation of an AES and
   * HMAC key.
   */
  byte[] getEncoded() {
    return Util.lenPrefixPack(aesKey.getEncoded(), hmacKey.getEncoded());
  }

  @Override
  protected Stream getStream() throws KeyczarException {
    return new AesStream();
  }

  @Override
  protected SecretKey getJceKey() {
    return aesKey;
  }

  private class AesStream implements EncryptingStream, DecryptingStream {
    private final Cipher encryptingCipher;
    private final Cipher decryptingCipher;
    private final SigningStream signStream;
    boolean ivRead = false;

    public AesStream() throws KeyczarException  {
      /*
       * The JCE Cipher.init() call essentially reallocates a new Cipher object
       * We avoid this by initializing two Cipher objects with zero-valued IVs,
       * Then passing IVs for CBC mode ourselves. The Ciphers will be cached in
       * this stream
       */
      IvParameterSpec zeroIv = new IvParameterSpec(new byte[BLOCK_SIZE]);
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
      byte[] iv = new byte[BLOCK_SIZE];
      input.get(iv);
      decryptingCipher.update(iv);
      ivRead = true;
    }

    @Override
    public int initEncrypt(ByteBuffer output) throws KeyczarException {
      // Generate a random value and encrypt it. This will be the IV.
      byte[] ivPreImage = new byte[BLOCK_SIZE];
      Util.rand(ivPreImage);
      try {
        return encryptingCipher.update(ByteBuffer.wrap(ivPreImage), output);
      } catch (javax.crypto.ShortBufferException e) {
        throw new ShortBufferException(e);
      }
    }

    @Override
    public int updateDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      if (ivRead && input.remaining() >= BLOCK_SIZE) {
        // The next output block will be the IV preimage, which we'll discard
        byte[] temp = new byte[BLOCK_SIZE];
        input.get(temp);
        decryptingCipher.update(temp);  // discard IV preimage byte array
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
        if (input.remaining() == 0) {
          // This can occur if someone encrypts an 0-length array
          return 0;
        }
        // The next output block will be the IV preimage, which we'll discard
        byte[] temp = new byte[BLOCK_SIZE];
        input.get(temp);
        decryptingCipher.update(temp);  // discard IV preimage byte array
        ivRead = false;
      }
      try {
        if (input.remaining() == 0) {
          byte[] outputBytes = decryptingCipher.doFinal();
          output.put(outputBytes);
          return outputBytes.length;
        } else {
          return decryptingCipher.doFinal(input, output);
        }
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
      return mode.getOutputSize(BLOCK_SIZE, inputLen);
    }
  }
}
