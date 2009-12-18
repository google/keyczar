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
import org.keyczar.annotations.Experimental;
import org.keyczar.exceptions.KeyczarException;

import java.util.Arrays;

/**
 * Tests Crypter class for encrypting and decrypting with RSA and AES. 
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
@Experimental
public class HybridTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  // Bigger than a public key block
  private byte[] bigInput = new byte[10000];
  private Encrypter encrypter;
  private Signer signer;
  private Crypter crypter;
  private Verifier verifier;
  private HybridEncrypter hybridEncrypter;
  private HybridDecrypter hybridDecrypter;
  
  @Override
  protected void setUp() throws Exception {
    encrypter = new Encrypter(TEST_DATA + "/rsa.public");
    signer = new Signer(TEST_DATA + "/dsa");
    hybridEncrypter = new HybridEncrypter(encrypter, signer);
    crypter = new Crypter(TEST_DATA + "/rsa");
    verifier = new Verifier(TEST_DATA + "/dsa.public");
  }
  
  @Test
  public final void testHybridEncryptAndDecrypt() throws KeyczarException {
    byte[] sessionMaterial = hybridEncrypter.getSessionMaterial();    
    byte[] hybridCiphertext = hybridEncrypter.encrypt(input.getBytes());
    hybridDecrypter =
      new HybridDecrypter(crypter, verifier, sessionMaterial);
    byte[] plaintext = hybridDecrypter.decrypt(hybridCiphertext);
    String decrypted = new String(plaintext);
    assertEquals(input, decrypted);
    
    // Try encrypting a bigger input under the same session key
    byte[] bigHybridCiphertext = hybridEncrypter.encrypt(bigInput);
    byte[] bigPlaintext = hybridDecrypter.decrypt(bigHybridCiphertext);
    assertTrue(Arrays.equals(bigInput, bigPlaintext));
  }
  
  @Test
  public final void testWrongSession() throws KeyczarException {
    byte[] sessionMaterial = hybridEncrypter.getSessionMaterial();    
    byte[] hybridCiphertext = hybridEncrypter.encrypt(input.getBytes());
    hybridDecrypter =
      new HybridDecrypter(crypter, verifier, sessionMaterial);
    
    // Instantiate a new hybrid encrypter 
    hybridEncrypter = new HybridEncrypter(encrypter, signer);
    byte[] moreSessionMaterial = hybridEncrypter.getSessionMaterial();
    HybridDecrypter anotherHybridDecrypter =
      new HybridDecrypter(crypter, verifier, moreSessionMaterial);
    
    try {
      // This should fail. It's trying to decrypt ciphertext from another session
      anotherHybridDecrypter.decrypt(hybridCiphertext);
      assertTrue(false);  // Should not be reached
    } catch (KeyczarException e) {
      // Expected
    }
  } 
}