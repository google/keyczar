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

import junit.framework.TestCase;

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.RsaPadding;

/**
 * Tests of X.509 certificate import functionality.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class CertificateImportTest extends TestCase {
  private static final String TEST_DATA = "./testdata/certificates/";
  private static final String[] FILE_FORMATS = { "pem", "der" };
  private static final String[] KEY_TYPES = { "rsa", "dsa" };
  private String input = "This is some test data";

  private void doTestCryptImport(String fileFormat) throws Exception {
    Encrypter encrypter =
        new Encrypter(new X509CertificateReader(KeyPurpose.ENCRYPT,
            new FileInputStream(TEST_DATA + "rsa-crypt-crt." + fileFormat), RsaPadding.OAEP));

    String ciphertext = encrypter.encrypt(input);
    String plaintext = new Crypter(TEST_DATA + "rsa-crypt").decrypt(ciphertext);
    assertEquals(input, plaintext);
  }

  public void testCryptImport() throws Exception {
    for (String format : FILE_FORMATS) {
      doTestCryptImport(format);
    }
  }

  private void doTestSignImport(String keyType, String fileFormat) throws Exception {
    String signature = new Signer(TEST_DATA + keyType + "-sign").sign(input);

    RsaPadding padding = null;
    if ("rsa".equals(keyType)) {
      padding = RsaPadding.OAEP;
    }

    Verifier verifier =
        new Verifier(new X509CertificateReader(KeyPurpose.VERIFY,
            new FileInputStream(TEST_DATA + keyType + "-sign-crt." + fileFormat), padding));
    assertTrue(verifier.verify(input, signature));
  }

  public void testSignerImport() throws Exception {
    for (String format : FILE_FORMATS) {
      for (String keyType : KEY_TYPES) {
        doTestSignImport(keyType, format);
      }
    }
  }
}
