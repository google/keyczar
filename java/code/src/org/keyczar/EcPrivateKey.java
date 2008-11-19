/*
 * Copyright 2008 Google Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.keyczar;

import com.google.gson.annotations.Expose;

import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.jce.EcCore;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Wrapping class for EC Private Keys
 * 
 * @author martclau@gmail.com
 * 
 */
class EcPrivateKey extends KeyczarKey implements KeyczarPrivateKey {
  private static final String KEY_GEN_ALGORITHM = "EC";
  private static final String SIG_ALGORITHM = "SHA256withECDSA";

  @Expose private EcPublicKey publicKey;
  @Expose private String pkcs8;

  private PrivateKey jcePrivateKey;

  private EcPrivateKey() {
    publicKey = new EcPublicKey();
  }

  public String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  public KeyczarPublicKey getPublic() {
    return publicKey;
  }
  
  @Override
  byte[] hash() {
    return getPublic().hash();
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new EcSigningStream();
  }

  @Override
  KeyType getType() {
    return KeyType.EC_PRIV;
  }

  public void setPublic(KeyczarPublicKey pub) throws KeyczarException {
    publicKey = (EcPublicKey) pub;
    publicKey.init();
  }

  static EcPrivateKey generate() throws KeyczarException {
    return generate(KeyType.EC_PRIV.defaultSize());
  }

  void init() throws KeyczarException {
    byte[] pkcs8Bytes = Base64Coder.decode(pkcs8);
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      jcePrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
      publicKey.init();
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }
  
  static EcPrivateKey generate(int keySize) throws KeyczarException {
    EcPrivateKey key = new EcPrivateKey();
    try {
      // Make sure we use our own impl; there may be other EC key generators...
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM,
          EcCore.NAME);
      key.size = keySize;
      kpg.initialize(key.size());
      KeyPair pair = kpg.generateKeyPair();
      key.jcePrivateKey = pair.getPrivate();
      key.publicKey.set(pair.getPublic().getEncoded());
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
    key.pkcs8 = Base64Coder.encode(key.jcePrivateKey.getEncoded());
    key.init();
    return key;
  }

  static EcPrivateKey read(String input) throws KeyczarException {
    EcPrivateKey key = Util.gson().fromJson(input, EcPrivateKey.class);
    key.init();
    return key;
  }

  private class EcSigningStream implements SigningStream, VerifyingStream {
    private Signature signature;
    private VerifyingStream verifyingStream;

    public EcSigningStream() throws KeyczarException {
      try {
        // Make sure we use our own impl; there may be other EC signature
        // generators...
        signature = Signature.getInstance(SIG_ALGORITHM, EcCore.NAME);
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
        signature.initSign(jcePrivateKey);
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
