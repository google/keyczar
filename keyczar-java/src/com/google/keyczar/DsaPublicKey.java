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
import com.google.keyczar.interfaces.Stream;
import com.google.keyczar.interfaces.VerifyingStream;
import com.google.keyczar.util.Base64Coder;
import com.google.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;


/**
 * Wrapping class for DSA Public Keys. These must be exported from existing DSA
 * private key sets.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 * 
 */
class DsaPublicKey extends KeyczarPublicKey {
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private static final String SIG_ALGORITHM = "SHA1withDSA";

  @Override
  public Stream getStream() throws KeyczarException {
    return new DsaVerifyingStream();
  }
  
  @Override
  String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  @Override
  KeyType getType() {
    return KeyType.DSA_PUB;
  }

  static DsaPublicKey read(String input) throws KeyczarException {
    DsaPublicKey key = Util.gson().fromJson(input, DsaPublicKey.class);
    if (key.getType() != KeyType.DSA_PUB) {
      throw new KeyczarException("Incorrect type. Received: " + key.getType());
    }
    key.init();
    return key;
  }

  private class DsaVerifyingStream implements VerifyingStream {
    private Signature signature;

    public DsaVerifyingStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
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
