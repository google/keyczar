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
import org.keyczar.exceptions.UnsupportedTypeException;
import org.keyczar.interfaces.EncryptingStream;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;


/**
 * Wrapping class for RSA Public Keys. These must be exported from existing RSA
 * private key sets.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
class RsaPublicKey extends KeyczarPublicKey {
  private static final String CRYPT_ALGORITHM =
    "RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING";
  private static final String KEY_GEN_ALGORITHM = "RSA";
  private static final String SIG_ALGORITHM = "SHA1withRSA";
  
  private RSAPublicKey jcePublicKey;
  @Expose String modulus;
  @Expose String publicExponent;

  private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  
  @Override
  public byte[] hash() {
    return hash;
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new RsaStream();
  }

  @Override
  KeyType getType() {
    return KeyType.RSA_PUB;
  }
  
  void set(BigInteger mod, BigInteger pubExp) throws KeyczarException {
    modulus = Base64Coder.encode(mod.toByteArray());
    publicExponent = Base64Coder.encode(pubExp.toByteArray());
    init();
  }
  
  void init() throws KeyczarException {
    byte[] modBytes = Base64Coder.decode(modulus);
    byte[] pubExpBytes = Base64Coder.decode(publicExponent);
    BigInteger mod = new BigInteger(modBytes);
    BigInteger pubExp = new BigInteger(pubExpBytes);
    // Sets the JCE Public key value
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, pubExp);
      jcePublicKey = (RSAPublicKey) kf.generatePublic(spec);
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
    byte[] fullHash = Util.prefixHash(Util.stripLeadingZeros(modBytes),
        Util.stripLeadingZeros(pubExpBytes));
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
  }

  static RsaPublicKey read(String input) throws KeyczarException {
    RsaPublicKey key = Util.gson().fromJson(input, RsaPublicKey.class);
    if (key.getType() != KeyType.RSA_PUB) {
      throw new UnsupportedTypeException(key.getType());
    }
    key.init();
    return key;
  }

  private class RsaStream implements VerifyingStream, EncryptingStream {
    private Cipher cipher;
    private Signature signature;

    public RsaStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        cipher = Cipher.getInstance(CRYPT_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
    }

    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public SigningStream getSigningStream() {
      return new SigningStream() {
        public int digestSize() {
          return 0;
        }

        public void initSign() {
          // Do nothing
        }

        public void sign(ByteBuffer output) {
          // Do nothing
        }

        public void updateSign(ByteBuffer input) {
          // Do nothing
        }
      };
    }

    public int initEncrypt(ByteBuffer output) throws KeyczarException {
      try {
        cipher.init(Cipher.ENCRYPT_MODE, jcePublicKey);
      } catch (InvalidKeyException e) {
        throw new KeyczarException(e);
      }
      return 0;
    }

    public void initVerify() throws KeyczarException {
      try {
        signature.initVerify(jcePublicKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int maxOutputSize(int inputLen) {
      return getType().getOutputSize();
    }

    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (ShortBufferException e) {
        throw new KeyczarException(e);
      }
    }

    public void updateVerify(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

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