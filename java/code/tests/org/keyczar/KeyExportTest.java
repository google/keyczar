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

import org.junit.Test;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;

/**
 * Test PKCS8 export functionality.
 *
 * TODO(swillden) After import functionality is added, make this a more thorough, round-trip
 * test.  Right now the only validation that the exported keys are in any way correct is done
 * manually, outside of this test.  Fixing that without import functionality would make the
 * test code dependent on the presence of openssl, which isn't a good idea.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class KeyExportTest extends TestCase {
  private static final String INVALID_PASSHRASE = "short";
  private static final String PASSPHRASE = "passphrase";
  private static final String TEST_DATA = "./testdata/certificates/";

  private void doTestImport(final String keyName, String expectedContent, String passphrase)
      throws KeyczarException {
    GenericKeyczar genericKeyczar = new GenericKeyczar(TEST_DATA + keyName);
    final String pemString = genericKeyczar.getPrimaryKey().getPemString(passphrase);
    assertTrue(pemString.contains(expectedContent));
  }

  @Test
  public void testRsaPrivateExport() throws KeyczarException {
    doTestImport("rsa-crypt", "BEGIN ENCRYPTED PRIVATE KEY", PASSPHRASE);
  }

  @Test
  public void testRsaPrivateExportNoPassphrase() {
    try {
      doTestImport("rsa-crypt", "BEGIN ENCRYPTED PRIVATE KEY", null);
      fail("Should throw");
    } catch (KeyczarException e) {
      assertEquals(Messages.getString("KeyczarTool.PassphraseRequired"), e.getMessage());
    }
  }

  @Test
  public void testRsaPrivateExportShortPassphrase() {
    try {
      doTestImport("rsa-crypt", "BEGIN ENCRYPTED PRIVATE KEY", INVALID_PASSHRASE);
      fail("Should throw");
    } catch (KeyczarException e) {
      assertEquals(Messages.getString("KeyczarTool.PassphraseRequired"), e.getMessage());
    }
  }

  @Test
  public void testRsaPublicExport() throws KeyczarException {
    doTestImport("rsa-crypt-pub", "BEGIN RSA PUBLIC KEY", null);
  }
  
  @Test
  public void testRsaPublicExportWithPassphrase() {
    try {
      doTestImport("rsa-crypt-pub", "BEGIN RSA PUBLIC KEY", PASSPHRASE);
      fail("Should throw");
    } catch (KeyczarException e) {
      assertEquals(Messages.getString("KeyczarTool.PassphraseNotAllowed"), e.getMessage());
    }
  }

  @Test
  public void testDsaPrivateExport() throws KeyczarException {
    doTestImport("dsa-sign", "BEGIN ENCRYPTED PRIVATE KEY", PASSPHRASE);
  }

  @Test
  public void testDsaPublicExport() throws KeyczarException {
    doTestImport("dsa-sign-pub", "BEGIN DSA PUBLIC KEY", null);
  }
}
