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
import java.io.InputStream;

import junit.framework.TestCase;

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;

/**
 * Tests PkcsKeyReader.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class PkcsImportTest extends TestCase {
  private static final String TEST_DATA = "./testdata/certificates/";
  private static final String[] FILE_FORMATS = { "pem", "der" };
  private static final String[] KEY_TYPES = { "rsa", "dsa" };
  private final String input = "This is some test data";

  public void testCryptImport() throws Exception {
    for (String format : FILE_FORMATS)  {
      doTestCryptImport("rsa", format);
    }
  }

  public void testSignImport() throws Exception {
    for (String keyType : KEY_TYPES) {
      for (String format : FILE_FORMATS) {
        doTestSignImport(keyType, format);
      }
    }
  }

  public void testImportDsaWithPadding() throws Exception {
    PkcsKeyReader reader = new PkcsKeyReader(KeyPurpose.SIGN_AND_VERIFY,
        getPkcs8KeyStream("dsa", "der", "sign"), RsaPadding.OAEP, "pass");
    try {
      reader.getKey();
      fail("Should throw");
    } catch (KeyczarException e) {
      assertTrue(e.getMessage().contains(RsaPadding.OAEP.name()));
    }
  }

  private void doTestCryptImport(String keyType, String fileFormat) throws Exception {
    Encrypter encrypter =
        new Encrypter(new PkcsKeyReader(KeyPurpose.ENCRYPT,
            getPkcs8KeyStream(keyType, fileFormat, "crypt"), RsaPadding.OAEP, "pass"));

    String ciphertext = encrypter.encrypt(input);
    String plaintext = new Crypter(TEST_DATA + "rsa-crypt").decrypt(ciphertext);
    assertEquals(input, plaintext);
  }

  private void doTestSignImport(String keyType, String fileFormat) throws Exception {
    RsaPadding padding = RsaPadding.OAEP;
    if (keyType.equals("dsa")) {
      padding = null;
    }

    final Signer signer =
        new Signer(new PkcsKeyReader(KeyPurpose.SIGN_AND_VERIFY,
          getPkcs8KeyStream(keyType, fileFormat, "sign"), padding, "pass"));

    String signature = signer.sign(input);
    assertTrue(new Verifier(TEST_DATA + keyType + "-sign").verify(input, signature));
  }

  private InputStream getPkcs8KeyStream(String keyType, String fileFormat, final String keyPurpose)
      throws FileNotFoundException {
    return new FileInputStream(TEST_DATA + keyType + "-" + keyPurpose + "-pkcs8." + fileFormat);
  }
}
