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
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAPublicKeySpec;

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

  private PublicKey jcePublicKey;
  @Expose String y;
  @Expose String p;
  @Expose String q;
  @Expose String g;

  private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];

  @Override
  public Stream getStream() throws KeyczarException {
    return new DsaVerifyingStream();
  }

  @Override
  KeyType getType() {
    return KeyType.DSA_PUB;
  }

  static DsaPublicKey read(String input) throws KeyczarException {
    DsaPublicKey key = Util.gson().fromJson(input, DsaPublicKey.class);
    key.init();
    return key;
  }
  
  @Override
  public byte[] hash() {
    return hash;
  }
  
  void set(BigInteger yVal, BigInteger pVal, BigInteger qVal, BigInteger gVal)
    throws KeyczarException {
    // Initialize the JSON fields
    y = Base64Coder.encode(yVal.toByteArray());
    p = Base64Coder.encode(pVal.toByteArray());
    q = Base64Coder.encode(qVal.toByteArray());
    g = Base64Coder.encode(gVal.toByteArray());
    init();
  }

  void init() throws KeyczarException {
    BigInteger yVal = new BigInteger(Base64Coder.decode(y));
    BigInteger pVal = new BigInteger(Base64Coder.decode(p));
    BigInteger qVal = new BigInteger(Base64Coder.decode(q));
    BigInteger gVal = new BigInteger(Base64Coder.decode(g));
    DSAPublicKeySpec spec = new DSAPublicKeySpec(yVal, pVal, qVal, gVal);
    
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      jcePublicKey = kf.generatePublic(spec);
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
    
    byte[] fullHash = Util.prefixHash(
        Util.stripLeadingZeros(pVal.toByteArray()),
        Util.stripLeadingZeros(qVal.toByteArray()),
        Util.stripLeadingZeros(gVal.toByteArray()),
        Util.stripLeadingZeros(yVal.toByteArray()));
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
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