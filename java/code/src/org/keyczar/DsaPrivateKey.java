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

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyType;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.keyparams.KeyParameters;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;

/**
 * Wrapping class for DSA Private Keys
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 */
public class DsaPrivateKey extends KeyczarKey implements KeyczarPrivateKey {
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private static final String SIG_ALGORITHM = "SHA1withDSA";
  private static final int DSA_DIGEST_SIZE = 48;

  @Expose private final DsaPublicKey publicKey;
  @Expose private final String x;

  private DSAPrivateKey jcePrivateKey;

  static DsaPrivateKey generate(KeyParameters params) throws KeyczarException {
    return new DsaPrivateKey(
        (DSAPrivateKey) Util.generateKeyPair(KEY_GEN_ALGORITHM, params.getKeySize()).getPrivate());
  }

  static DsaPrivateKey read(String input) throws KeyczarException {
    DsaPrivateKey key = Util.gson().fromJson(input, DsaPrivateKey.class);
    return key.initFromJson();
  }

  public DsaPrivateKey(DSAPrivateKey privateKey) throws KeyczarException {
    super(privateKey.getParams().getP().bitLength());
    publicKey = new DsaPublicKey(privateKey);
    jcePrivateKey = privateKey;
    x = Base64Coder.encodeWebSafe(jcePrivateKey.getX().toByteArray());
  }

  // Used by GSON, which will overwrite the values set here.
  private DsaPrivateKey() {
    super(0);
    publicKey = null;
    x = null;
  }

  @Override
  protected byte[] hash() {
    return getPublic().hash();
  }

  public String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  @Override
  public KeyczarPublicKey getPublic() {
    return publicKey;
  }

  @Override
  protected Stream getStream() throws KeyczarException {
    return new DsaSigningStream();
  }

  @Override
  public KeyType getType() {
    return DefaultKeyType.DSA_PRIV;
  }

  /**
   * Initialize JCE key from JSON data.  Must be called after an instance is read from JSON.
   */
  private DsaPrivateKey initFromJson() throws KeyczarException {
    publicKey.initFromJson();

    BigInteger xVal = new BigInteger(Base64Coder.decodeWebSafe(x));
    BigInteger pVal = new BigInteger(Base64Coder.decodeWebSafe(publicKey.p));
    BigInteger qVal = new BigInteger(Base64Coder.decodeWebSafe(publicKey.q));
    BigInteger gVal = new BigInteger(Base64Coder.decodeWebSafe(publicKey.g));
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      final DSAPrivateKeySpec spec = new DSAPrivateKeySpec(xVal, pVal, qVal, gVal);
      jcePrivateKey = (DSAPrivateKey) kf.generatePrivate(spec);
      return this;
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  @Override
  protected DSAPrivateKey getJceKey() {
    return jcePrivateKey;
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

    @Override
    public int digestSize() {
      return DSA_DIGEST_SIZE;
    }

    @Override
    public void initSign() throws KeyczarException {
      try {
        signature.initSign(jcePrivateKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify() throws KeyczarException {
      verifyingStream.initVerify();
    }

    @Override
    public void sign(ByteBuffer output) throws KeyczarException {
      try {
        byte[] sig = signature.sign();
        output.put(sig);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateSign(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateVerify(ByteBuffer input) throws KeyczarException {
      verifyingStream.updateVerify(input);
    }

    @Override
    public boolean verify(ByteBuffer sig) throws KeyczarException {
      return verifyingStream.verify(sig);
    }
  }
}
