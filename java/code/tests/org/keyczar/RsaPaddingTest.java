// Copyright 2011 Google Inc. All Rights Reserved.

package org.keyczar;

import com.google.gson.JsonParseException;

import junit.framework.TestCase;

import org.junit.Before;
import org.junit.Test;
import org.keyczar.RsaPublicKey.Padding;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Util;

/**
 * This test case verifies that OAEP and PKCS1 v1.5 padding are both supported for RSA keys.
 * 
 * @author swillden@google.com (Shawn Willden)
 */
public class RsaPaddingTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private KeyczarReader fileReader;
  private KeyczarReader oaepReader;
  private KeyczarReader pkcsReader;
  
  @Before
  @Override
  public void setUp() {
    fileReader = new KeyczarFileReader(TEST_DATA + "/rsa");
    oaepReader = new AddPaddingKeyczarReader(fileReader, "OAEP");
    pkcsReader = new AddPaddingKeyczarReader(fileReader, "PKCS");
  }

  /**
   * Tests that an RSA key with no explicitly-specified padding defaults to OAEP.
   */
  @Test
  public void testPaddingDefault() throws KeyczarException {
    // First ensure the primary key doesn't contain explicit padding info, in case
    // someone changed the key in the test data.
    final String keyData = fileReader.getKey();
    assertFalse("Key should not contain padding field", keyData.toLowerCase().contains("padding"));

    // Now check that the padding is defaulted to OAEP
    final RsaPublicKey pubKey = getPublicKey(new Encrypter(fileReader));
    assertEquals(RsaPublicKey.Padding.OAEP, pubKey.getPadding());
  }

  /**
   * Tests that an RSA key with PKCS padding has PKCS padding.
   */
  @Test
  public void testPaddingPkcs() throws KeyczarException {
    final RsaPublicKey pubKey = getPublicKey(new Encrypter(pkcsReader));
    assertEquals(RsaPublicKey.Padding.PKCS, pubKey.getPadding());
  }

  /**
   * Verifies that key loading fails if the padding field is invalid.
   */
  @Test
  public void testLoadInvalidPadding() throws KeyczarException {
    try {
      new Encrypter(new AddPaddingKeyczarReader(fileReader, "INVALID"));
      fail("Should throw");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("INVALID"));
    }
  }

  /**
   * Verifies that data encrypted with OAEP padding cannot be decrypted with PKCS padding.
   */
  @Test
  public void testIncompatibility() throws KeyczarException {
    final Encrypter encrypter = new Encrypter(oaepReader);
    assertEquals(Padding.OAEP, getPublicKey(encrypter).getPadding());
    final String ciphertext = encrypter.encrypt(TEST_DATA);

    final Crypter crypter = new Crypter(pkcsReader);
    assertEquals(Padding.PKCS, getPublicKey(crypter).getPadding());
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
   * A KeyczarReader wrapper that alters the returned keys to specify a caller-selected
   * padding type in place of the original padding (if any).
   * 
   * @author swillden@google.com (Shawn Willden)
   */
  private class AddPaddingKeyczarReader implements KeyczarReader {
    private final KeyczarReader wrappedReader;
    private final String paddingString;

    public AddPaddingKeyczarReader(KeyczarReader wrappedReader, String paddingString) {
      this.paddingString = paddingString;
      this.wrappedReader = wrappedReader;
    }

    @Override
    public String getKey(int version) throws KeyczarException {
      return setPadding(wrappedReader.getKey(version));
    }

    @Override
    public String getKey() throws KeyczarException {
      return setPadding(wrappedReader.getKey());
    }

    @Override
    public String getMetadata() throws KeyczarException {
      return wrappedReader.getMetadata();
    }

    /**
     * Sets the padding field in the key string, which must be an RSA private key string.
     * 
     * The input string may not have a padding field at all, so we covert it to and
     * from a key object before doing the field replacement, which will add a default
     * padding value if none is present.
     */
    private String setPadding(String jsonString) {
      RsaPrivateKey privKey = Util.gson().fromJson(jsonString, RsaPrivateKey.class);
      RsaPublicKey pubKey = (RsaPublicKey) privKey.getPublic();
      String publicKeyString = Util.gson().toJson(pubKey);
      
      // check invalid padding
      Padding localPadding = Padding.valueOf(paddingString);
      
      if (localPadding == Padding.PKCS) {
        pubKey.setPadding(Padding.PKCS);
        String jsonPubStringWithPadding = Util.gson().toJson(pubKey);
        // replace public key in private key.
        return jsonString.replace(publicKeyString, jsonPubStringWithPadding);
      }
      
      return jsonString;
    }
  }
}
