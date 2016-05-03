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
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.UnsupportedTypeException;
import org.keyczar.interfaces.EncryptingStream;
import org.keyczar.interfaces.KeyType;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;


/**
 * Wrapping class for RSA Public Keys. These must be exported from existing RSA
 * private key sets.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class RsaPublicKey extends KeyczarPublicKey {
  private static final String KEY_GEN_ALGORITHM = "RSA";
  private static final String SIG_ALGORITHM = "SHA1withRSA";

  private RSAPublicKey jcePublicKey;
  final String modulus;
  final String publicExponent;
  final RsaPadding padding;

  private final byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  static RsaPublicKey read(String input) throws KeyczarException {
    try {
      return fromJson(new JSONObject(input));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  static RsaPublicKey fromJson(JSONObject json) throws KeyczarException, JSONException {
    RsaPublicKey key = new RsaPublicKey(
        json.getInt("size"),
        json.getString("modulus"),
        json.getString("publicExponent"),
        Util.deserializeEnum(RsaPadding.class, json.optString("padding")));

    if (key.getType() != DefaultKeyType.RSA_PUB) {
      throw new UnsupportedTypeException(key.getType());
    }
    return key.initFromJson();
  }

  @Override
  JSONObject toJson() {
    try {
      return new JSONObject()
        .put("size", size)
        .put("modulus", modulus)
        .put("publicExponent", publicExponent)
        .put("padding", padding != null ? padding.name() : null);
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] hash() {
    return hash;
  }
  
  public Iterable<byte[]> fallbackHash() {
    return super.fallbackHash();
  }

  @Override
  protected Stream getStream() throws KeyczarException {
    Stream cachedStream = cachedStreams.poll();
    if (cachedStream != null) {
      return cachedStream;
    } 
    return new RsaStream();
  }

  @Override
  public KeyType getType() {
    return DefaultKeyType.RSA_PUB;
  }

  RsaPublicKey(RSAPrivateCrtKey privateKey, RsaPadding padding) throws KeyczarException {
    this(privateKey.getModulus(), privateKey.getPublicExponent(), padding);
    initializeJceKey(privateKey.getModulus(), privateKey.getPublicExponent());
    initializeHash();
  }

  RsaPublicKey(RSAPublicKey publicKey, RsaPadding padding) throws KeyczarException {
    this(publicKey.getModulus(), publicKey.getPublicExponent(), padding);
    jcePublicKey = publicKey;
    initializeHash();
  }

  private RsaPublicKey(int size, String modulus, String publicExponent, RsaPadding padding) {
    super(size);
    this.modulus = modulus;
    this.publicExponent = publicExponent;
    this.padding = padding;
  }

  private RsaPublicKey(BigInteger mod, BigInteger exp, RsaPadding padding) {
    super(mod.bitLength());
    this.modulus = Util.encodeBigInteger(mod);
    this.publicExponent = Util.encodeBigInteger(exp);
    this.padding = (padding == RsaPadding.PKCS) ? RsaPadding.PKCS : null;
  }

  /**
   * Initialize JCE key from JSON data.  Must be called after an instance is read from JSON.
   * In default scope so {@link RsaPrivateKey} can call it when a private key string (which
   * contains a public key string) is deserialized.
   */
  RsaPublicKey initFromJson() throws KeyczarException {
    initializeJceKey(Util.decodeBigInteger(modulus), Util.decodeBigInteger(publicExponent));
    initializeHash();
    return this;
  }

  private void initializeJceKey(BigInteger publicModulus, BigInteger publicExponent)
      throws KeyczarException {
    try {
      RSAPublicKeySpec spec = new RSAPublicKeySpec(publicModulus, publicExponent);
      jcePublicKey = (RSAPublicKey) KeyFactory.getInstance(KEY_GEN_ALGORITHM).generatePublic(spec);
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  private void initializeHash() throws KeyczarException {
    System.arraycopy(getPadding().computeFullHash(jcePublicKey), 0, hash, 0, hash.length);
  }

  int keySizeInBytes() {
    return jcePublicKey.getModulus().bitLength() / 8;
  }

  @Override
  protected RSAPublicKey getJceKey() {
    return jcePublicKey;
  }

  @Override
  protected boolean isSecret() {
    return false;
  }

  /**
   * Returns the padding used when this key is used to encrypt data.
   */
  public RsaPadding getPadding() {
    if (padding == null || padding == RsaPadding.OAEP) {
      return RsaPadding.OAEP;
    } else {
      return RsaPadding.PKCS;
    }
  }

  private class RsaStream implements VerifyingStream, EncryptingStream {
    private Cipher cipher;
    private Signature signature;

    RsaStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        cipher = Cipher.getInstance(getPadding().getCryptAlgorithm());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int digestSize() {
      return keySizeInBytes();
    }

    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        final int ciphertextSize = cipher.getOutputSize(input.limit());
        final int outputCapacity = output.limit() - output.position();

        ByteBuffer tmpOutput = ByteBuffer.allocate(ciphertextSize);
        cipher.doFinal(input, tmpOutput);

        if (ciphertextSize == outputCapacity) {
          output.put(tmpOutput.array());

        } else if (ciphertextSize == (outputCapacity + 1)
            && tmpOutput.array()[ciphertextSize - 1] == 0) {
          // There exists at least one JCE (the one IBM ships with some versions of
          // Websphere) which outputs ciphertext that's one byte too long, appending
          // a trailing zero.  We need to trim this byte.
          output.put(tmpOutput.array(), 0, outputCapacity);

        } else {
          throw new KeyczarException("Expected " + outputCapacity + " bytes from encryption "
              + "operation but got " + ciphertextSize);
        }

        return outputCapacity;
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public SigningStream getSigningStream() {
      return new SigningStream() {
        @Override
        public int digestSize() {
          return 0;
        }

        @Override
        public void initSign() {
          // Do nothing
        }

        @Override
        public void sign(ByteBuffer output) {
          // Do nothing
        }

        @Override
        public void updateSign(ByteBuffer input) {
          // Do nothing
        }
      };
    }

    @Override
    public int initEncrypt(ByteBuffer output) throws KeyczarException {
      try {
        cipher.init(Cipher.ENCRYPT_MODE, jcePublicKey);
      } catch (InvalidKeyException e) {
        throw new KeyczarException(e);
      }
      return 0;
    }

    @Override
    public void initVerify() throws KeyczarException {
      try {
        signature.initVerify(jcePublicKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int maxOutputSize(int inputLen) {
      return keySizeInBytes();
    }

    @Override
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (ShortBufferException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateVerify(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public boolean verify(ByteBuffer sig) throws KeyczarException {
      try {
        return signature.verify(sig.array(), sig.position(), sig.limit()
            - sig.position());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
  }
}
