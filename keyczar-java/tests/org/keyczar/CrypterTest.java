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


import java.io.RandomAccessFile;
import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortCiphertextException;
import org.keyczar.interfaces.KeyczarReader;

/**
 * Tests Crypter class for encrypting and decrypting with RSA and AES. 
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */

public class CrypterTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  
  private final void testDecrypt(String subDir) throws Exception {
    testDecrypt(new KeyczarFileReader(TEST_DATA + subDir), subDir);
  }

  private final void testDecrypt(KeyczarReader reader, String subDir)
      throws Exception {
    Crypter crypter = new Crypter(reader);
    RandomAccessFile activeInput =
      new RandomAccessFile(TEST_DATA + subDir + "/1.out", "r");
    String activeCiphertext = activeInput.readLine(); 
    activeInput.close();
    RandomAccessFile primaryInput =
      new RandomAccessFile(TEST_DATA + subDir + "/2.out", "r");
    String primaryCiphertext = primaryInput.readLine();
    primaryInput.close();
    String activeDecrypted = crypter.decrypt(activeCiphertext);
    assertEquals(input, activeDecrypted);
    String primaryDecrypted = crypter.decrypt(primaryCiphertext);
    assertEquals(input, primaryDecrypted);
  }
  
  @Test
  public final void testAesDecrypt() throws Exception {
    testDecrypt("/aes");
  }
  
  @Test 
  public final void testAesEncryptedKeyDecrypt() throws Exception {
    // Test reading and using encrypted keys
    KeyczarFileReader fileReader =
      new KeyczarFileReader(TEST_DATA + "/aes-crypted");
    Crypter keyDecrypter = new Crypter(TEST_DATA + "/aes");
    KeyczarEncryptedReader reader =
      new KeyczarEncryptedReader(fileReader, keyDecrypter);
    testDecrypt(reader, "/aes-crypted");
  }
  
  @Test
  public final void testRsaDecrypt() throws Exception  {
    testDecrypt("/rsa");
  }
  
  @Test
  public final void testAesEncryptAndDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    String ciphertext = crypter.encrypt(input);
    System.out.println("Aes Ciphertext: " + ciphertext);
    String decrypted = crypter.decrypt(ciphertext);
    assertEquals(input, decrypted);
  }

  @Test
  public final void testRsaEncryptAndDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/rsa");
    String ciphertext = crypter.encrypt(input);
    System.out.println("Rsa Ciphertext: " + ciphertext);
    String decrypted = crypter.decrypt(ciphertext);
    assertEquals(input, decrypted);
  }
  
  @Test
  public final void testShortAesEncryptAndDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    for (int i = 0; i < 32; i++) {
      char[] letters = new char[i];
      Arrays.fill(letters, 'a');
      String input = new String(letters);
      String ciphertext = crypter.encrypt(input);
      String decrypted = crypter.decrypt(ciphertext);
      assertEquals(input, decrypted);
    }
  }

  @Test
  public final void testBadAesCiphertexts() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    try {
      crypter.decrypt(new byte[0]);  // discard garbage decrypted output
    } catch (ShortCiphertextException e) {
      // Expected exception
    }
    byte[] ciphertext = crypter.encrypt(input.getBytes());
    // Munge the ciphertext
    ciphertext[1] ^= 44;
    try {
      crypter.decrypt(ciphertext);  // discard garbage decrypted output
    } catch (KeyNotFoundException e) {
      // Expected exception
    }    
  }
}