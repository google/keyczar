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

import org.junit.Test;
import org.keyczar.interfaces.KeyczarReader;

import junit.framework.TestCase;

import java.io.RandomAccessFile;

/**
 * These tests read keys that were exported from a reference implementation.
 * It will be used to ensure that this Keyczar implementation is
 * cross-compatible. 
 *
 * @author steveweis@gmail.com (Steve Weis)
 */

public class CrossCompatibilityTest extends TestCase {
  private static final String TEST_DATA = "./testdata/crosscomp";
  private String plaintext = "This is not a test, this is a real string";
  private String morePlaintext = "Some text to encrypt";
  private final void testDecrypt(KeyczarReader reader, String subDir)
      throws Exception {
  }

  @Test
  public final void testAesDecrypt() throws Exception {
    String dir = TEST_DATA + "/aes";
    Crypter crypter = new Crypter(dir);
    RandomAccessFile activeInput =
      new RandomAccessFile(dir + "/1.out", "r");
    String activeCiphertext = activeInput.readLine(); 
    activeInput.close();
    RandomAccessFile primaryInput =
     new RandomAccessFile(dir + "/2.out", "r");
    String primaryCiphertext = primaryInput.readLine();
    primaryInput.close();
    String activeDecrypted = crypter.decrypt(activeCiphertext);
    assertEquals(morePlaintext, activeDecrypted);
    String primaryDecrypted = crypter.decrypt(primaryCiphertext);
    assertEquals(plaintext, primaryDecrypted);
  }
  
  @Test
  public final void testRsaDecrypt() throws Exception {
    String dir = TEST_DATA + "/rsa";
    Crypter crypter = new Crypter(dir);
    RandomAccessFile primaryInput =
     new RandomAccessFile(dir + "/1.out", "r");
    String primaryCiphertext = primaryInput.readLine();
    primaryInput.close();
    byte[] foo = crypter.encrypt("Bar".getBytes());
    
    String primaryDecrypted = crypter.decrypt(primaryCiphertext);
    assertEquals(plaintext, primaryDecrypted);
  }

  private final void testSignature(String dir) throws Exception {
    Signer signer = new Signer(dir);
    RandomAccessFile input =
      new RandomAccessFile(dir + "/1.out", "r");
    String signature = input.readLine(); 
    input.close();
    assertTrue(signer.verify(plaintext, signature));
  }
  
  @Test
  public final void testHmacVerify() throws Exception {
    String dir = TEST_DATA + "/hmac";
    testSignature(dir);
  }
  
  @Test
  public final void testDsaVerify() throws Exception {
    String dir = TEST_DATA + "/dsa";
    testSignature(dir);
  }
}
