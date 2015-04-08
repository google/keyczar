/*
 * Copyright 2011 Google Inc.
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

import junit.framework.TestCase;

import org.junit.Before;
import org.junit.Test;
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;

/**
 * This test case verifies that OAEP and PKCS1 v1.5 padding are both supported for RSA keys.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class RsaPaddingTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private KeyczarReader defaultReader;
  private KeyczarReader oaepReader;
  private KeyczarReader pkcsReader;
  private KeyczarReader invalidReader;

  private static final String metadataString =
      "{\"name\":\"\",\"purpose\":\"DECRYPT_AND_ENCRYPT\",\"type\":\"RSA_PRIV\",\"version"
          + "s\":[{\"exportable\":false,\"status\":\"PRIMARY\",\"versionNumber\":1}],\"en"
          + "crypted\":false}";

  private static final String pubKeyStringPrefix =
      "{\"modulus\":\"ANRvrByiiuvqU53_8EdhXR_ieDX7gsMpnHTRZn8vuPRlooLcVg_TP_6DrkHDT1kSfso"
          + "OMkpCw6dv7qJEqHS8kO7qUwBh3ZtM02-9jc0VY--Pjp8uFeq6SMkCa8EpzSyBSjucOoUi-yqs0-g"
          + "KGGgd_0N88A37aGNedtCWqyePYsi7\",\"publicExponent\":\"AQAB\",\"size\":1024";
  private static final String pubKeyStringSuffix = "}";

  private static final String oaepPaddingString = ",\"padding\":\"OAEP\"";
  private static final String pkcsPaddingString = ",\"padding\":\"PKCS\"";
  private static final String invalidPaddingString = ",\"padding\":\"INVALID\"";

  private static final String privKeyStringPrefix = "{\"publicKey\":";
  private static final String privKeyStringSuffix =
      ",\"privateExponent\":\"KAq4lVkp-Ffd1P1GDB5VEEp-wCYdOq4gOICz4itboG172VCwxCDcghvN_8V"
          + "Rsodi8LEGV6sH-AqIH3vziLV2V8pXV6E4ZxpmKQVM4vtK0P-cHz3IExXzQaM5q-BrYNuzhl-Qzs9"
          + "lsD5IxNPQYwGgDAL5yl_e1z41VDyfOCqQZIE\",\"primeP\":\"AOlnBr4i8vKddjvRr2upGTcl"
          + "gRxQbqOwvXdcif6hFk_7iBxwAfltDzSlDR1Zx2i2IaSJJOQEilvBPcYx8Lq9_0E\",\"primeQ\""
          + ":\"AOkA_VZjN7PQkJgDxcpvn_ptFCpdKhA0NPBu9PmocaUKmfyF-KQK6bZf5-gOgCvy01KdIx_xy"
          + "DPf8bres9x8hPs\",\"primeExponentP\":\"ANfFINyhnotfui_u1wbmWqM6jrNIQCAfgehYql"
          + "G1RdVHKTtw6MJXahk3BHq_xrMsvMlI58vLzsSoTp1tCaj5gIE\",\"primeExponentQ\":\"ALl"
          + "66jB8pvjjTFdWmXr-xPELKARZSYTAqmvDSAv9hQoGmHInC7k6XrWpPujBslJJ6ONY538kb2SsHrf"
          + "NVIxuK0U\",\"crtCoefficient\":\"AM-mryy-gC1CHOpA-Mtqfe3pM6IIcsQfiLRswtez5mid"
          + "jb4Gy7juZKHIuPz_t7y0s2C4mSXsqwi2W5gj9MqbXUw\",\"size\":1024}";

  private String buildKey(String paddingString) {
    return privKeyStringPrefix
        + pubKeyStringPrefix
        + paddingString
        + pubKeyStringSuffix
        + privKeyStringSuffix;
  }

  @Before
  @Override
  public void setUp() {

    defaultReader = new StaticKeyczarReader(metadataString, buildKey(""));
    oaepReader = new StaticKeyczarReader(metadataString, buildKey(oaepPaddingString));
    pkcsReader = new StaticKeyczarReader(metadataString, buildKey(pkcsPaddingString));
    invalidReader = new StaticKeyczarReader(metadataString, buildKey(invalidPaddingString));
  }

  /**
   * Tests that an RSA key with no explicitly-specified padding defaults to OAEP.
   */
  @Test
  public void testPaddingDefault() throws KeyczarException {
    // First ensure the primary key doesn't contain explicit padding info, in case
    // someone changed the key in the test data.
    final String keyData = buildKey("");
    assertFalse("Key should not contain padding field", keyData.toLowerCase().contains("padding"));

    // Now check that the padding is defaulted to OAEP
    final RsaPublicKey pubKey = getPublicKey(new Encrypter(defaultReader));
    assertEquals(RsaPadding.OAEP, pubKey.getPadding());
  }

  /**
   * Tests that an RSA key with PKCS padding has PKCS padding.
   */
  @Test
  public void testPaddingPkcs() throws KeyczarException {
    final RsaPublicKey pubKey = getPublicKey(new Encrypter(pkcsReader));
    assertEquals(RsaPadding.PKCS, pubKey.getPadding());
  }

  /**
   * Verifies that key loading fails if the padding field is invalid.
   */
  @Test
  public void testLoadInvalidPadding() throws KeyczarException {
    try {
      new Encrypter(invalidReader);
      fail("Should throw");
    } catch (RuntimeException e) {
      assertTrue(e.getMessage().contains("INVALID"));
    }
  }

  /**
   * Verifies that data encrypted with OAEP padding cannot be decrypted with PKCS padding.
   */
  @Test
  public void testIncompatibility() throws KeyczarException {
    final Encrypter encrypter = new Encrypter(oaepReader);
    assertEquals(RsaPadding.OAEP, getPublicKey(encrypter).getPadding());
    final String ciphertext = encrypter.encrypt(TEST_DATA);

    final Crypter crypter = new Crypter(pkcsReader);
    assertEquals(RsaPadding.PKCS, getPublicKey(crypter).getPadding());
    try {
      crypter.decrypt(ciphertext);
      fail("Should throw");
    } catch (KeyNotFoundException e) {
      // Don't check exception message because we can't know what language it's in.
    }
  }

  private RsaPublicKey getPublicKey(final Keyczar keyczar) {
    return (RsaPublicKey) ((RsaPrivateKey) keyczar.getPrimaryKey()).getPublic();
  }

  /**
   * Verifies that data encrypted with PKCS padding can be decrypted with PKCS padding
   */
  @Test
  public void testPkcsEncryption() throws KeyczarException {
    final String ciphertext = new Encrypter(pkcsReader).encrypt(TEST_DATA);
    final String plaintext = new Crypter(pkcsReader).decrypt(ciphertext);
    assertEquals(TEST_DATA, plaintext);
  }

  /**
   * Verifies that OAEP and PKCS padding keys have different hashes.
   */
  @Test
  public void testHashMismatch() throws KeyczarException {
    final RsaPublicKey oaepPaddingKey = getPublicKey(new Encrypter(oaepReader));
    final RsaPublicKey pkcsPaddingKey = getPublicKey(new Encrypter(pkcsReader));

    assertFalse(oaepPaddingKey.hash().equals(pkcsPaddingKey.hash()));
  }

  /**
   * A KeyczarReader that retrurns static data.
   *
   * @author swillden@google.com (Shawn Willden)
   */
  private class StaticKeyczarReader implements KeyczarReader {
    private final String metadata;
    private final String key;

    public StaticKeyczarReader(String metadata, String key) {
      this.metadata = metadata;
      this.key = key;
    }

    @Override
    public String getKey(int version) {
      return key;
    }

    @Override
    public String getKey() {
      return key;
    }

    @Override
    public String getMetadata() {
      return metadata;
    }
  }
}
