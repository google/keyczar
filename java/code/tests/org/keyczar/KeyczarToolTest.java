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
import org.keyczar.KeyczarTool;
import org.keyczar.MockKeyczarReader;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;

/**
 * 
 * Mocks out KeyczarReader and uses it to influence the creation of a
 * GenericKeyCzar that reads metadata and key info from our mock.
 * 
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 * 
 */
public class KeyczarToolTest extends TestCase {
  private static final String TEST_DATA = "./testdata/certificates/";
  
  MockKeyczarReader mock;
  MockKeyczarReader pubMock;
  
  @Override
  public final void setUp() throws KeyczarException {
    mock = new MockKeyczarReader("TEST", KeyPurpose.ENCRYPT, KeyType.AES);
    mock.addKey(42, KeyStatus.PRIMARY);
    mock.addKey(77, KeyStatus.ACTIVE);
    mock.addKey(99, KeyStatus.INACTIVE);
    
    pubMock = new MockKeyczarReader("PUBLIC-TEST", 
        KeyPurpose.DECRYPT_AND_ENCRYPT, KeyType.RSA_PRIV);
    
    KeyczarTool.setReader(mock); // use mock reader
  }
  
  @Test
  public final void testCreate() {
    String[] args = {"create", "--name=create-test", "--purpose=test"};
    assertEquals("TEST", mock.name());
    assertEquals(KeyPurpose.ENCRYPT, mock.purpose());
    assertEquals(KeyType.AES, mock.type());
    KeyczarTool.main(args);
    assertEquals("create-test", mock.name());
    assertEquals(KeyPurpose.TEST, mock.purpose());
    assertEquals(KeyType.TEST, mock.type());
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
    assertEquals(192, mock.getKeySize(4)); // adding fourth key
  }
  
  @Test
  public final void testPublicKeys() throws KeyczarException {
    pubMock.addKey(33, KeyStatus.PRIMARY, 512); // use 512-bit keys for speed
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
  public final void testImportCertificate() {
    String[] args = {"importkey", "--pemfile=" + TEST_DATA + "rsa-crypt-crt.pem" };
    assertEquals(3, mock.numKeys());
    KeyczarTool.main(args);
    assertEquals(4, mock.numKeys());
    assertTrue(mock.existsVersion(4));
  }

  @Override
  public final void tearDown() {
    KeyczarTool.setReader(null); // remove mock reader
    mock = null;
    pubMock = null;
  }
}