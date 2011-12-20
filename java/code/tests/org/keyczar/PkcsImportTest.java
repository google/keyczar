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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.BadPaddingException;

import junit.framework.TestCase;

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;

/**
 * Tests PkcsKeyReader.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class PkcsImportTest extends TestCase {
  private static final String TEST_DATA = "./testdata/certificates/";
  private static final String[] FILE_FORMATS = { "pem", "der" };
  private static final String[] KEY_TYPES = { "rsa", "dsa" };
  private static final String INPUT = "This is some test data";

  /**
   * Tests importing decryption keys in PEM and DER formats.  Verifies that the imported
   * private key can successfully decrypt a message encrypted with the corresponding
   * Keyczar-format public key.  Also verifies that a corrupted message fails to decrypt.
   */
  public void testCryptImport() throws Exception {
    for (String format : FILE_FORMATS)  {
      doTestCryptImport(getPkcs8KeyStream("rsa", format, "crypt"));
    }
  }

  /**
   * Tests importing RSA and DSA signing keys in PEM and DER formats.  Verifies that the
   * imported private signing key generates a signature that can be verified with the
   * corresponding Keycar-format public key.  Also verifies that a corrupted signature
   * or a corrupted message fail to verify.
   */
  public void testSignImport() throws Exception {
    for (String keyType : KEY_TYPES) {
      for (String format : FILE_FORMATS) {
        doTestSignImport(keyType, getPkcs8KeyStream(keyType, format, "sign"));
      }
    }
  }

  /**
   * Verifies that trying to import a DSA key with an RSA padding specifier fails with the
   * correct exception.
   */
  public void testImportDsaWithPadding() throws Exception {
    PkcsKeyReader reader =
        new PkcsKeyReader(KeyPurpose.SIGN_AND_VERIFY, getPkcs8KeyStream("dsa", "der", "sign"),
            RsaPadding.OAEP, "pass");
    try {
      reader.getKey();
      fail("Should throw");
    } catch (KeyczarException e) {
      assertTrue(e.getMessage().contains(RsaPadding.OAEP.name()));
    }
  }

  /**
   * Verifies that trying to import corrupted PKCS#8 keys fails with the correct exception.
   */
  public void testCryptImportCorrupted() throws Exception {
    for (String format : FILE_FORMATS)  {
      try {
        doTestCryptImport(new CorruptedStream(getPkcs8KeyStream("rsa", format, "crypt")));
      } catch (KeyczarException e) {
        assertTrue(e.getMessage().contains("PKCS"));
      }
    }
  }

  private void doTestCryptImport(InputStream pkcs8KeyStream) throws Exception {
    final String ciphertext = new Encrypter(TEST_DATA + "rsa-crypt").encrypt(INPUT);
    final Crypter decrypter = new Crypter(new PkcsKeyReader(
        KeyPurpose.DECRYPT_AND_ENCRYPT, pkcs8KeyStream, RsaPadding.OAEP, "pass"));
    assertEquals(INPUT, decrypter.decrypt(ciphertext));

    // Try with corrupted ciphertext
    final byte[] ciphertextBytes = Base64Coder.decodeWebSafe(ciphertext);
    ciphertextBytes[ciphertextBytes.length / 2] ^= 0xFF;
    try {
      decrypter.decrypt(Base64Coder.encodeWebSafe(ciphertextBytes));
    } catch (KeyczarException e) {
      assertTrue(e.getCause() instanceof BadPaddingException);
    }
  }

  private void doTestSignImport(String keyType, InputStream pkcs8KeyStream) throws Exception {
    RsaPadding padding = RsaPadding.OAEP;
    if (keyType.equals("dsa")) {
      padding = null;
    }

    final String signature = new Signer(TEST_DATA + keyType + "-sign").sign(INPUT);
    final Verifier verifier = new Verifier(
        new PkcsKeyReader(KeyPurpose.SIGN_AND_VERIFY, pkcs8KeyStream, padding, "pass"));
    assertTrue(verifier.verify(INPUT, signature));

    // Try with corrupted signature
    final byte[] signatureBytes = Base64Coder.decodeWebSafe(signature);
    signatureBytes[signatureBytes.length / 2] ^= 0xFF;
    assertFalse(verifier.verify(INPUT, Base64Coder.encodeWebSafe(signatureBytes)));

    // Try with corrupted message
    assertFalse(verifier.verify("wrong input", signature));
  }

  private InputStream getPkcs8KeyStream(String keyType, String fileFormat, String keyPurpose)
      throws FileNotFoundException {
    return new FileInputStream(TEST_DATA + keyType + "-" + keyPurpose + "-pkcs8." + fileFormat);
  }

  /**
   * An input stream that corrupts every tenth byte by inverting it.
   */
  private class CorruptedStream extends InputStream {
    private final InputStream inStream;
    private int count = 0;

    public CorruptedStream(InputStream inStream) {
      this.inStream = inStream;
    }

    @Override
    public int read() throws IOException {
      int b = inStream.read();
      if (b == -1 || ((++count % 10) != 0)) {
        return b;
      } else {
        return (byte)(b ^ 0xFF);
      }
    }
  }
}
