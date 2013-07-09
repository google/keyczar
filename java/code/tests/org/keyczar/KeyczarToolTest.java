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

import junit.framework.TestCase;

import org.junit.Test;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.NoPrimaryKeyException;
import org.keyczar.i18n.Messages;
import org.keyczar.keyparams.RsaKeyParameters;

/**
 *
 * Mocks out KeyczarReader and uses it to influence the creation of a
 * GenericKeyCzar that reads metadata and key info from our mock.
 *
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public class KeyczarToolTest extends TestCase {
  private final static class FastRsaKeyParameters implements RsaKeyParameters {
    @Override
    public int getKeySize() {
      return 1024; // use 1024-bit keys for speed
    }

    @Override
    public RsaPadding getRsaPadding() {
      return RsaPadding.OAEP;
    }
  }

  private static final String TEST_DATA = "./testdata/certificates/";

  MockKeyczarReader mock;
  MockKeyczarReader pubMock;

  @Override
  public final void setUp() throws KeyczarException {
    mock = new MockKeyczarReader("TEST", KeyPurpose.ENCRYPT, DefaultKeyType.AES);
    mock.addKey(42, KeyStatus.PRIMARY);
    mock.addKey(77, KeyStatus.ACTIVE);
    mock.addKey(99, KeyStatus.INACTIVE);

    pubMock = new MockKeyczarReader("PUBLIC-TEST",
        KeyPurpose.DECRYPT_AND_ENCRYPT, DefaultKeyType.RSA_PRIV);

    KeyczarTool.setReader(mock); // use mock reader
  }

  @Test
  public final void testCreate() {
    String[] args = {"create", "--name=create-test", "--purpose=test"};
    assertEquals("TEST", mock.name());
    assertEquals(KeyPurpose.ENCRYPT, mock.purpose());
    assertEquals(DefaultKeyType.AES, mock.type());
    KeyczarTool.main(args);
    assertEquals("create-test", mock.name());
    assertEquals(KeyPurpose.TEST, mock.purpose());
    assertEquals(DefaultKeyType.TEST, mock.type());
  }

  @Test
  public final void testAddKey() {
    assertEquals(3, mock.numKeys());
    String[] args = {"addkey", "--status=primary"};
    KeyczarTool.main(args);
    assertEquals(4, mock.numKeys());
    assertEquals(KeyStatus.ACTIVE, mock.getStatus(42));
    // can only have one primary key, old primary key should be demoted
  }

  @Test
  public final void testAddKeySizeFlag() {
    String[] args = {"addkey", "--status=active", "--size=192"};
    KeyczarTool.main(args);
    assertTrue(mock.existsVersion(100));
    assertEquals(192, mock.getKeySize(100)); // adding fourth key
  }

  @Test
  public final void testPublicKeys() throws KeyczarException {
    pubMock.addKey(33, KeyStatus.PRIMARY, new FastRsaKeyParameters());
    KeyczarTool.setReader(pubMock); // use pubMock reader instead
    assertFalse(pubMock.exportedPublicKeySet());
    String[] args = {"pubkey"};
    KeyczarTool.main(args);
    assertTrue(pubMock.exportedPublicKeySet());
    assertTrue(pubMock.hasPublicKey(33));
  }

  @Test
  public final void testPromote() {
    String[] args = {"promote", "--version=77"};
    KeyczarTool.main(args);
    assertEquals(KeyStatus.PRIMARY, mock.getStatus(77));
    assertEquals(KeyStatus.ACTIVE, mock.getStatus(42));
  }

  @Test
  public final void testDemote() {
    String[] args = {"demote", "--version=77"};
    KeyczarTool.main(args);
    assertEquals(KeyStatus.INACTIVE, mock.getStatus(77));
  }

  @Test
  public final void testRevoke() {
    String[] args = {"revoke", "--version=99"};
    assertTrue(mock.existsVersion(99));
    KeyczarTool.main(args);
    assertFalse(mock.existsVersion(99));
  }

  @Test
  public final void testAddAfterRevoke() throws KeyczarException {
    mock = new MockKeyczarReader("TEST", KeyPurpose.ENCRYPT, DefaultKeyType.AES);
    assertEquals(0, mock.numKeys());
    KeyczarTool.setReader(mock);

    // Add a pair of keys
    String[] addKeyArgs = {"addkey", "--status=primary"};
    KeyczarTool.main(addKeyArgs);
    assertTrue(mock.existsVersion(1));
    assertFalse(mock.existsVersion(2));
    KeyczarTool.main(addKeyArgs);
    assertTrue(mock.existsVersion(1));
    assertTrue(mock.existsVersion(2));

    // Demote and revoke version 1
    String[] demoteArgs = {"demote", "--version=1"};
    KeyczarTool.main(demoteArgs);
    assertTrue(mock.existsVersion(1));
    assertTrue(mock.existsVersion(2));
    String[] revokeArgs = {"revoke", "--version=1"};
    KeyczarTool.main(revokeArgs);
    assertFalse(mock.existsVersion(1));
    assertTrue(mock.existsVersion(2));
    String key2 = mock.getKey(2);

    // Add a third key
    KeyczarTool.main(addKeyArgs);
    assertFalse(mock.existsVersion(1));
    assertTrue(mock.existsVersion(2));
    assertEquals(key2, mock.getKey(2));
    assertTrue(mock.existsVersion(3));
  }

  @Test
  public final void testImportCertificateAsActive() throws KeyczarException {
    KeyczarTool.setReader(pubMock); // use pubMock reader instead

    String[] args = {"importkey", "--pemfile=" + TEST_DATA + "rsa-crypt-crt.pem"};
    assertEquals(0, pubMock.numKeys());
    KeyczarTool.main(args);
    assertEquals(1, pubMock.numKeys());
    assertTrue(pubMock.existsVersion(1));
    assertEquals(KeyStatus.ACTIVE, pubMock.getStatus(1));
    try {
      new GenericKeyczar(pubMock).getMetadata().getPrimaryVersion();
    } catch (NoPrimaryKeyException e) {
      assertEquals(Messages.getString("NoPrimaryKeyFound"), e.getMessage());
    }
    assertFalse(pubMock.getKey(1).contains("\"PKCS\""));
  }

  @Test
  public final void testImportCertificateAsPrimary() throws KeyczarException {
    KeyczarTool.setReader(pubMock); // use pubMock reader instead

    assertEquals(0, pubMock.numKeys());
    KeyczarTool.main(new String[] { "importkey", "--pemfile=" + TEST_DATA + "rsa-crypt-crt.pem",
        "--status=primary"});
    assertEquals(1, pubMock.numKeys());
    assertTrue(pubMock.existsVersion(1));
    assertEquals(KeyStatus.PRIMARY, pubMock.getStatus(1));
    assertFalse(pubMock.getKey(1).contains("\"PKCS\""));

    KeyczarTool.main(new String[] { "importkey", "--pemfile=" + TEST_DATA + "rsa-sign-crt.pem",
        "--status=primary"});
    assertEquals(2, pubMock.numKeys());
    assertTrue(pubMock.existsVersion(2));
    assertEquals(KeyStatus.ACTIVE, pubMock.getStatus(1));
    assertEquals(KeyStatus.PRIMARY, pubMock.getStatus(2));
  }

  @Test
  public final void testImportCertificateWithPkcsPadding() throws KeyczarException {
    String[] args = {"importkey", "--pemfile=" + TEST_DATA + "rsa-crypt-crt.pem", "--padding=PKCS"};
    assertEquals(3, mock.numKeys());
    KeyczarTool.main(args);
    assertEquals(4, mock.numKeys());
    assertTrue(mock.existsVersion(100));
    assertFalse(mock.getKey(100).contains("\"OAEP\""));
    assertTrue(mock.getKey(100).contains("\"PKCS\""));
  }

  @Test
  public final void testImportPkcsRsaKey() throws KeyczarException {
    String[] args = {"importkey",
                     "--pemfile=" + TEST_DATA + "rsa-crypt-pkcs8.pem",
                     "--passphrase=pass"};
    assertEquals(3, mock.numKeys());
    KeyczarTool.main(args);
    assertEquals(4, mock.numKeys());
    assertTrue(mock.existsVersion(100));
    assertTrue("Should contain a private key", mock.getKey(100).contains("primeP"));
  }

  @Test
  public final void testImportPkcsRsaKeyNoPassphrase() {
    String[] args = {"importkey",
                     "--pemfile=" + TEST_DATA + "rsa-crypt-pkcs8.pem" };

    assertEquals(3, mock.numKeys());
    KeyczarTool.main(args);
    assertEquals(3, mock.numKeys());
  }

  @Test
  public final void testImportPkcsDsaKey() throws KeyczarException {
    String[] args = {"importkey",
                     "--pemfile=" + TEST_DATA + "dsa-sign-pkcs8.pem",
                     "--passphrase=pass"};

    assertEquals(3, mock.numKeys());
    KeyczarTool.main(args);
    assertEquals(4, mock.numKeys());
    assertTrue(mock.existsVersion(100));
    assertTrue("Should contain a private key", mock.getKey(100).contains("\"x\":"));
  }

  @Test
  public final void testImportPkcsDsaKeyNoPassphrase() {
    String[] args = {"importkey",
                     "--pemfile=" + TEST_DATA + "dsa-sign-pkcs8.pem" };

    assertEquals(3, mock.numKeys());
    KeyczarTool.main(args);
    assertEquals(3, mock.numKeys());
  }

  @Test
  public final void testHelp() {
    String[] args = {};
    KeyczarTool.main(args);
  }

  /**
   * Tests adding a new primary key to an empty key set.
   */
  @Test
  public final void testAddNewKey() {
    mock = new MockKeyczarReader("TEST", KeyPurpose.ENCRYPT, DefaultKeyType.AES);
    KeyczarTool.setReader(mock); // use mock reader
    assertEquals(0, mock.numKeys());
    String[] args = {"addkey", "--status=primary"};
    KeyczarTool.main(args);
    assertEquals(1, mock.numKeys());
    assertEquals(KeyStatus.PRIMARY, mock.getStatus(1));
  }

  // TODO(swillden) Add export tests.

  @Override
  public final void tearDown() {
    KeyczarTool.setReader(null); // remove mock reader
    mock = null;
    pubMock = null;
  }
}
