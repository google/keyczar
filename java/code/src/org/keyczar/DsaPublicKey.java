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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;

/**
 * Wrapping class for DSA Public Keys. These must be exported from existing DSA
 * private key sets.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class DsaPublicKey extends KeyczarPublicKey {
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private static final String SIG_ALGORITHM = "SHA1withDSA";
  private static final int DSA_DIGEST_SIZE = 48;

  private DSAPublicKey jcePublicKey;
  private final byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose final String y;
  @Expose final String p;
  @Expose final String q;
  @Expose final String g;

  static DsaPublicKey read(String input) throws KeyczarException {
    DsaPublicKey key = Util.gson().fromJson(input, DsaPublicKey.class);
    key.initFromJson();
    return key;
  }

  /**
   * Constructs a new {@link DsaPublicKey} from the provided JCE {@link DSAPublicKey}.
   */
  DsaPublicKey(DSAPublicKey jcePublicKey) throws KeyczarException {
    this(jcePublicKey.getY(), jcePublicKey.getParams());
  }

  /**
   * Constructs a new {@link DsaPublicKey} from the provided JCE {@link DSAPrivateKey}.
   */
  DsaPublicKey(DSAPrivateKey jcePrivateKey) throws KeyczarException {
    this(computeY(jcePrivateKey), jcePrivateKey.getParams());
  }

  // Used by GSON, which will overwrite the values set here.
  private DsaPublicKey() {
    super(0);
    jcePublicKey = null;
    y = p = q = g = null;
  }

  private DsaPublicKey(BigInteger yVal, DSAParams params) throws KeyczarException {
    super(params.getP().bitLength());
    BigInteger pVal = params.getP();
    BigInteger qVal = params.getQ();
    BigInteger gVal = params.getG();
    y = Base64Coder.encodeWebSafe(yVal.toByteArray());
    p = Base64Coder.encodeWebSafe(pVal.toByteArray());
    q = Base64Coder.encodeWebSafe(qVal.toByteArray());
    g = Base64Coder.encodeWebSafe(gVal.toByteArray());
    initializeJceKey(yVal, pVal, qVal, gVal);
    initializeHash();
  }

  private static BigInteger computeY(DSAPrivateKey jcePrivateKey) {
    final BigInteger p = jcePrivateKey.getParams().getP();
    final BigInteger g = jcePrivateKey.getParams().getG();
    final BigInteger x = jcePrivateKey.getX();
    return g.modPow(x, p);
  }

  @Override
  protected Stream getStream() throws KeyczarException {
    return new DsaVerifyingStream();
  }

  @Override
  public KeyType getType() {
    return DefaultKeyType.DSA_PUB;
  }

  @Override
  public byte[] hash() {
    return hash;
  }

  /**
   * Initialize JCE key from JSON data.  Must be called after an instance is read from JSON.
   * In default scope so {@link DsaPrivateKey} can call it when a private key string (which
   * contains a public key string) is deserialized.
   */
  void initFromJson() throws KeyczarException {
    BigInteger yVal = new BigInteger(Base64Coder.decodeWebSafe(y));
    BigInteger pVal = new BigInteger(Base64Coder.decodeWebSafe(p));
    BigInteger qVal = new BigInteger(Base64Coder.decodeWebSafe(q));
    BigInteger gVal = new BigInteger(Base64Coder.decodeWebSafe(g));
    initializeJceKey(yVal, pVal, qVal, gVal);
    initializeHash();
  }

  private void initializeJceKey(BigInteger yVal, BigInteger pVal, BigInteger qVal,
      BigInteger gVal) throws KeyczarException {
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      jcePublicKey = (DSAPublicKey) kf.generatePublic(new DSAPublicKeySpec(yVal, pVal, qVal, gVal));
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  private void initializeHash() throws KeyczarException {
    final DSAParams dsaParams = jcePublicKey.getParams();
    final byte[] fullHash = Util.prefixHash(
        Util.stripLeadingZeros(dsaParams.getP().toByteArray()),
        Util.stripLeadingZeros(dsaParams.getQ().toByteArray()),
        Util.stripLeadingZeros(dsaParams.getG().toByteArray()),
        Util.stripLeadingZeros(jcePublicKey.getY().toByteArray()));
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
  }

  @Override
  protected PublicKey getJceKey() {
    return jcePublicKey;
  }

  @Override
  protected boolean isSecret() {
    return false;
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

    @Override
    public int digestSize() {
      return DSA_DIGEST_SIZE;
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
