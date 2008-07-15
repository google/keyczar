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
import com.google.keyczar.exceptions.UnsupportedTypeException;
import com.google.keyczar.i18n.Messages;
import com.google.keyczar.interfaces.EncryptingStream;
import com.google.keyczar.interfaces.SigningStream;
import com.google.keyczar.interfaces.Stream;
import com.google.keyczar.interfaces.VerifyingStream;
import com.google.keyczar.util.Base64Coder;
import com.google.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;

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
    "RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING"; //$NON-NLS-1$
  private static final String KEY_GEN_ALGORITHM = "RSA"; //$NON-NLS-1$
  private static final String SIG_ALGORITHM = "SHA1withRSA"; //$NON-NLS-1$

  @Override
  String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new RsaStream();
  }

  @Override
  KeyType getType() {
    return KeyType.RSA_PUB;
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

    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
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
        cipher.init(Cipher.ENCRYPT_MODE, getJcePublicKey());
      } catch (InvalidKeyException e) {
        throw new KeyczarException(e);
      }
      return 0;
    }

    @Override
    public void initVerify() throws KeyczarException {
      try {
        signature.initVerify(getJcePublicKey());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int maxOutputSize(int inputLen) {
      return getType().getOutputSize();
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
