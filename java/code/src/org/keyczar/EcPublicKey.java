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
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Wrapping class for EC Public Keys. These must be exported from existing EC
 * private key sets.
 * 
 * @author martclau@gmail.com
 * 
 */
class EcPublicKey extends KeyczarPublicKey {
  private static final String KEY_GEN_ALGORITHM = "EC";
  private static final String SIG_ALGORITHM = "SHA256withECDSA";

  private PublicKey jcePublicKey;
  @Expose String x509;

  private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  
  void init() throws KeyczarException {
    byte[] x509Bytes = Base64Coder.decode(x509);
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      jcePublicKey = kf.generatePublic(new X509EncodedKeySpec(x509Bytes));
      byte[] fullHash = Util.prefixHash(x509Bytes);
      System.arraycopy(fullHash, 0, hash, 0, hash.length);
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  void set(byte[] x509Bytes) throws KeyczarException {
    x509 = Base64Coder.encode(x509Bytes);
    byte[] fullHash = Util.prefixHash(x509Bytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    init();
  }
  
  @Override
  byte[] hash() {
    return hash;
  }
  
  @Override
  public Stream getStream() throws KeyczarException {
    return new EcVerifyingStream();
  }

  @Override
  KeyType getType() {
    return KeyType.EC_PUB;
  }

  static EcPublicKey read(String input) throws KeyczarException {
    EcPublicKey key = Util.gson().fromJson(input, EcPublicKey.class);
    key.init();
    return key;
  }

  private class EcVerifyingStream implements VerifyingStream {
    private Signature signature;

    public EcVerifyingStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
    }

    public void initVerify() throws KeyczarException {
      try {
        signature.initVerify(jcePublicKey);
      } catch (GeneralSecurityException e) {
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
