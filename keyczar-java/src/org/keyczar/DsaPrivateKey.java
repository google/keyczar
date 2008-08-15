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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Wrapping class for DSA Private Keys
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
class DsaPrivateKey extends KeyczarPrivateKey {
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private static final String SIG_ALGORITHM = "SHA1withDSA";

  @Expose private DsaPublicKey publicKey;

  private DsaPrivateKey() {
    publicKey = new DsaPublicKey();
  }

  @Override
  String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  @Override
  KeyczarPublicKey getPublic() {
    return publicKey;
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new DsaSigningStream();
  }

  @Override
  KeyType getType() {
    return KeyType.DSA_PRIV;
  }

  @Override
  void setPublic(KeyczarPublicKey pub) throws KeyczarException {
    publicKey = (DsaPublicKey) pub;
    publicKey.init();
  }

  static DsaPrivateKey generate() throws KeyczarException {
    return generate(KeyType.DSA_PRIV.defaultSize());
  }

  static DsaPrivateKey generate(int keySize) throws KeyczarException {
    DsaPrivateKey key = new DsaPrivateKey();
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM);
      key.size = keySize;
      kpg.initialize(key.size());
      KeyPair pair = kpg.generateKeyPair();
      key.jcePrivateKey = pair.getPrivate();
      key.getPublic().set(pair.getPublic().getEncoded());
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
    key.pkcs8 = Base64Coder.encode(key.jcePrivateKey.getEncoded());
    key.init();
    return key;
  }

  static DsaPrivateKey read(String input) throws KeyczarException {
    DsaPrivateKey key = Util.gson().fromJson(input, DsaPrivateKey.class);
    key.init();
    return key;
  }

  private class DsaSigningStream implements SigningStream, VerifyingStream {
    private Signature signature;
    private VerifyingStream verifyingStream;

    public DsaSigningStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        verifyingStream = (VerifyingStream) publicKey.getStream();
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
    }

    public void initSign() throws KeyczarException {
      try {
        signature.initSign(getJcePrivateKey());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public void initVerify() throws KeyczarException {
      verifyingStream.initVerify();
    }

    public void sign(ByteBuffer output) throws KeyczarException {
      try {
        byte[] sig = signature.sign();
        output.put(sig);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    public void updateSign(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    public void updateVerify(ByteBuffer input) throws KeyczarException {
      verifyingStream.updateVerify(input);
    }

    public boolean verify(ByteBuffer sig) throws KeyczarException {
      return verifyingStream.verify(sig);
    }
  }
}