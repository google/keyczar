/*
 * Copyright 2010 Google Inc.
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

import org.apache.log4j.Logger;
import org.junit.Test;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;

/**
 * Tests Crypter class for encrypting and decrypting with RSA and AES.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
@SuppressWarnings("deprecation")
public class SessionTest extends TestCase {
  private static final Logger LOG = Logger.getLogger(SessionTest.class);
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  // Bigger than a public key block
  private byte[] bigInput = new byte[10000];
  private Encrypter publicKeyEncrypter;
  private Crypter privateKeyDecrypter;
  private SessionEncrypter sessionEncrypter;
  private SessionCrypter sessionCrypter;
  private SessionDecrypter sessionDecrypter;

  @Override
  protected void setUp() throws Exception {
    publicKeyEncrypter = new Encrypter(TEST_DATA + "/rsa.public");
    sessionEncrypter = new SessionEncrypter(publicKeyEncrypter);
    sessionCrypter = new SessionCrypter(publicKeyEncrypter);
    privateKeyDecrypter = new Crypter(TEST_DATA + "/rsa");
  }

  @Test
  public final void testEncryptAndDecrypt() throws KeyczarException {
    byte[] sessionMaterial = sessionEncrypter.getSessionMaterial();
    String sessionMaterialString = Base64Coder.encodeWebSafe(sessionMaterial);
    LOG.debug(String.format("Encoded session material: %s", sessionMaterialString));
    byte[] ciphertext = sessionEncrypter.encrypt(input.getBytes());
    String ciphertextString = Base64Coder.encodeWebSafe(ciphertext);
    LOG.debug(String.format("Encoded ciphertext: %s", ciphertextString));
    sessionDecrypter = new SessionDecrypter(privateKeyDecrypter, sessionMaterial);
    byte[] plaintext = sessionDecrypter.decrypt(ciphertext);
    String decrypted = new String(plaintext);
    assertEquals(input, decrypted);

    // Try encrypting a bigger input under the same session key
    byte[] bigCiphertext = sessionEncrypter.encrypt(bigInput);
    byte[] bigPlaintext = sessionDecrypter.decrypt(bigCiphertext);
    assertTrue(Arrays.equals(bigInput, bigPlaintext));
  }

  @Test
  public final void testDecrypt() throws KeyczarException, IOException {
    RandomAccessFile sessionMaterialInput =
      new RandomAccessFile(TEST_DATA + "/rsa/session.material.out", "r");
    String sessionMaterialString = sessionMaterialInput.readLine();
    sessionMaterialInput.close();
    byte[] sessionMaterial = Base64Coder.decodeWebSafe(sessionMaterialString);

    RandomAccessFile sessionCiphertextInput =
      new RandomAccessFile(TEST_DATA + "/rsa/session.ciphertext.out", "r");
    String sessionCiphertextString = sessionCiphertextInput.readLine();
    sessionCiphertextInput.close();
    byte[] sessionCiphertext = Base64Coder.decodeWebSafe(sessionCiphertextString);
    sessionDecrypter =
      new SessionDecrypter(privateKeyDecrypter, sessionMaterial);
    byte[] plaintext = sessionDecrypter.decrypt(sessionCiphertext);
    String decrypted = new String(plaintext);
    assertEquals(input, decrypted);
  }

  @Test
  public final void testWrongSession() throws KeyczarException {
    byte[] sessionMaterial = sessionEncrypter.getSessionMaterial();
    byte[] ciphertext = sessionEncrypter.encrypt(input.getBytes());
    sessionDecrypter =
      new SessionDecrypter(privateKeyDecrypter, sessionMaterial);

    // Instantiate a new hybrid encrypter
    sessionEncrypter = new SessionEncrypter(publicKeyEncrypter);
    byte[] moreSessionMaterial = sessionEncrypter.getSessionMaterial();
    SessionDecrypter anotherHybridDecrypter =
      new SessionDecrypter(privateKeyDecrypter, moreSessionMaterial);
    try {
      // This should fail. It's trying to decrypt ciphertext from another session
      anotherHybridDecrypter.decrypt(ciphertext);
      assertTrue(false);  // Should not be reached
    } catch (KeyczarException e) {
      // Expected
    }
  }

  @Test
  public final void testCrypterDecryptsOwnCiphertext() throws KeyczarException {
    byte[] ciphertext = sessionCrypter.encrypt(input.getBytes());
    String ciphertextString = Base64Coder.encodeWebSafe(ciphertext);
    LOG.debug(String.format("Encoded ciphertext: %s", ciphertextString));

    byte[] plaintext = sessionCrypter.decrypt(ciphertext);
    String decrypted = new String(plaintext);
    assertEquals(input, decrypted);

    // Try encrypting a bigger input under the same session key
    byte[] bigCiphertext = sessionCrypter.encrypt(bigInput);
    byte[] bigPlaintext = sessionCrypter.decrypt(bigCiphertext);
    assertTrue(Arrays.equals(bigInput, bigPlaintext));
  }

  @Test
  public final void testCrypterDecryptsResponse() throws KeyczarException {
    byte[] sessionMaterial = sessionCrypter.getSessionMaterial();
    byte[] packedKey = privateKeyDecrypter.decrypt(sessionMaterial);

    AesKey aesKey = AesKey.fromPackedKey(packedKey);
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    Crypter symmetricCrypter = new Crypter(importedKeyReader);

    byte[] ciphertextResponse = symmetricCrypter.encrypt(input.getBytes());
    byte[] plaintext = sessionCrypter.decrypt(ciphertextResponse);
    String decrypted = new String(plaintext);

    assertEquals(input, decrypted);

    // Try encrypting a bigger input under the same session key
    byte[] bigCiphertext = symmetricCrypter.encrypt(bigInput);
    byte[] bigPlaintext = sessionCrypter.decrypt(bigCiphertext);
    assertTrue(Arrays.equals(bigInput, bigPlaintext));
  }

  @Test
  public final void testCrypterPair() throws KeyczarException {
     SessionCrypter localCrypter = new SessionCrypter(publicKeyEncrypter);

     byte[] encrypted = localCrypter.encrypt(input.getBytes());
     byte[] sessionMaterial = localCrypter.getSessionMaterial();

     SessionCrypter remoteCrypter =
         new SessionCrypter(privateKeyDecrypter, sessionMaterial);

     byte[] decrypted = remoteCrypter.decrypt(encrypted);
     assertTrue(Arrays.equals(input.getBytes(), decrypted));

     encrypted = remoteCrypter.encrypt(bigInput);
     decrypted = localCrypter.decrypt(encrypted);
     assertTrue(Arrays.equals(bigInput, decrypted));
  }
}
