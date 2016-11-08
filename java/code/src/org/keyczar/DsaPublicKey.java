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

  // See DsaVerifyingStream.verify
  private static boolean strictVerification = Boolean.valueOf(
      System.getProperty("keyczar.strict_dsa_verification", "false"));

  // visible for testing
  public static void setStrictVerificationForTest(boolean strictVerification) {
    DsaPublicKey.strictVerification = strictVerification;
  }

  private DSAPublicKey jcePublicKey;
  private final byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  final String y;
  final String p;
  final String q;
  final String g;

  static DsaPublicKey read(String input) throws KeyczarException {
    try {
      DsaPublicKey key = fromJson(new JSONObject(input));
      key.initFromJson();
      return key;
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  static DsaPublicKey fromJson(JSONObject json) throws JSONException {
    return new DsaPublicKey(
        json.getInt("size"),
        json.getString("y"),
        json.getString("p"),
        json.getString("q"),
        json.getString("g"));
  }

  @Override
  JSONObject toJson() {
    try {
      return new JSONObject()
        .put("size", size)
        .put("y", y)
        .put("p", p)
        .put("q", q)
        .put("g", g);
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
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

  // Used by JSON
  private DsaPublicKey(int size, String y, String p, String q, String g) {
    super(size);
    jcePublicKey = null;
    this.y = y;
    this.p = p;
    this.q = q;
    this.g = g;
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
    Stream cachedStream = cachedStreams.poll();
    if (cachedStream != null) {
      return cachedStream;
    }
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

  @Override
  public Iterable<byte[]> fallbackHash() {
    return super.fallbackHash();
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
    byte[] fullHash = Util.prefixHash(
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
        // Copy the signature so that it can be safely modified
        ByteBuffer signatureToVerify = ByteBuffer.allocate(sig.limit() - sig.position());
        signatureToVerify.put(sig.array(), sig.position(), sig.limit()
            - sig.position());
        if (!strictVerification) {
          // A DSA signature is a DER sequence tag, following by a varint length that indicates
          // length of the rest of the signature. This code truncates the signature to the indicated
          // length.

          // This is necessary since older versions of KeyCzar had a bug that included extra bytes
          // at the end of the signature.

          // if at any point we find something that is not as expected, stop processing and let it
          // just fall through the the JCE.


          // Start at the beginning and assume that we will truncate - set the flag to false if
          // anything happens that is unexpected.
          signatureToVerify.position(0);
          boolean truncateSignature = true;
          // Look for a DER sequence tag
          if (signatureToVerify.get() != 0x30) {
            truncateSignature = false;
          } else {
            // Now look for the DER length of the signature, which can be at most 48 bytes, so will
            // only be 1 byte in DER varint.
            int coefficientLength = signatureToVerify.get() & 0x00FF;
            if (coefficientLength >= 0x80) {
              // Nope - this means it's not a DSA 1024 SHA 1 signature
              truncateSignature = false;
            } else if (
                signatureToVerify.position() + coefficientLength > signatureToVerify.limit()) {
              // Nope - this is also not a well formed DSA 1024 SHA 1 signature
              truncateSignature = false;
            } else {
              // Advance to the first byte past the signature
              signatureToVerify.position(signatureToVerify.position() + coefficientLength);
            }
          }
          if (truncateSignature) {
            int bytesToTruncate = signatureToVerify.limit() - signatureToVerify.position();
            if (bytesToTruncate > 0) {
              signatureToVerify.limit(signatureToVerify.position());
            }
          }
        }

        // Now do the actual verify
        signatureToVerify.position(0);
        return signature.verify(signatureToVerify.array(),
            signatureToVerify.position(),
            signatureToVerify.limit() - signatureToVerify.position());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
  }
}
