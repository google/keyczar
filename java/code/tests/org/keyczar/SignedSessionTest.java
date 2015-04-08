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

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;
import org.keyczar.annotations.Experimental;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;

/**
 * Tests signed session encryption and decryption
 * with RSA, DSA and AES.
 *
 * @author normandl@google.com (David Norman)
 */
@Experimental
public class SignedSessionTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  // Bigger than a public key block
  private byte[] bigInput = new byte[10000];
  private Encrypter publicKeyEncrypter;
  private Crypter privateKeyDecrypter;
  private Signer privateKeySigner;
  private Verifier publicKeyVerifier;
  private SignedSessionEncrypter sessionEncrypter;
  private SignedSessionDecrypter sessionDecrypter;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    publicKeyEncrypter = new Encrypter(TEST_DATA + "/rsa.public");
    privateKeySigner = new Signer(TEST_DATA + "/dsa");
    sessionEncrypter = new SignedSessionEncrypter(publicKeyEncrypter, privateKeySigner);
    privateKeyDecrypter = new Crypter(TEST_DATA + "/rsa");
    publicKeyVerifier = new Verifier(TEST_DATA + "/dsa.public");
  }

  @Test
  public final void testEncryptAndDecrypt() throws KeyczarException {
    // create a new session, already encrypted and encoded.
    String sessionMaterialString = sessionEncrypter.newSession();

    // perform encryption
    byte[] ciphertext = sessionEncrypter.encrypt(input.getBytes());
    String ciphertextString = Base64Coder.encodeWebSafe(ciphertext);

    // perform decryption
    sessionDecrypter =
        new SignedSessionDecrypter(privateKeyDecrypter, publicKeyVerifier, sessionMaterialString);
    byte[] plaintext = sessionDecrypter.decrypt(ciphertext);
    String decrypted = new String(plaintext);
    assertEquals(input, decrypted);

    // Try encrypting a bigger input under the same session key
    byte[] bigCiphertext = sessionEncrypter.encrypt(bigInput);
    byte[] bigPlaintext = sessionDecrypter.decrypt(bigCiphertext);
    assertTrue(Arrays.equals(bigInput, bigPlaintext));
  }

  @Test
  public final void testEncryptAndDecryptWithRsaSigner() throws KeyczarException {
    publicKeyEncrypter = new Encrypter(TEST_DATA + "/rsa.public");
    privateKeySigner = new Signer(TEST_DATA + "/rsa-sign");
    sessionEncrypter = new SignedSessionEncrypter(publicKeyEncrypter, privateKeySigner);
    privateKeyDecrypter = new Crypter(TEST_DATA + "/rsa");
    publicKeyVerifier = new Verifier(TEST_DATA + "/rsa-sign.public");

    // create a new session, already encrypted and encoded.
    String sessionMaterialString = sessionEncrypter.newSession();

    // perform encryption
    byte[] ciphertext = sessionEncrypter.encrypt(input.getBytes());
    String ciphertextString = Base64Coder.encodeWebSafe(ciphertext);

    // perform decryption
    sessionDecrypter =
        new SignedSessionDecrypter(privateKeyDecrypter, publicKeyVerifier, sessionMaterialString);
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
        new RandomAccessFile(TEST_DATA + "/signedsession/signed.session.out", "r");
    String sessionMaterialString = sessionMaterialInput.readLine();
    sessionMaterialInput.close();

    RandomAccessFile sessionCiphertextInput =
        new RandomAccessFile(TEST_DATA + "/signedsession/signed.ciphertext.out", "r");
    String sessionCiphertextString = sessionCiphertextInput.readLine();
    sessionCiphertextInput.close();
    byte[] sessionCiphertext = Base64Coder.decodeWebSafe(sessionCiphertextString);
    sessionDecrypter =
        new SignedSessionDecrypter(privateKeyDecrypter, publicKeyVerifier, sessionMaterialString);
    byte[] plaintext = sessionDecrypter.decrypt(sessionCiphertext);
    String decrypted = new String(plaintext);
    assertEquals(input, decrypted);
  }

  @Test
  public final void testWrongSession() throws KeyczarException {
    // gen a new session, to work with offsetting sessions.
    sessionEncrypter.newSession();
    byte[] ciphertext = sessionEncrypter.encrypt(input.getBytes());

    // Instantiate a new hybrid encrypter
    String newSessionMaterialString = sessionEncrypter.newSession();
    sessionDecrypter = new SignedSessionDecrypter(privateKeyDecrypter, publicKeyVerifier,
        newSessionMaterialString);
    try {
      // This should fail. It's trying to decrypt ciphertext from another session
      sessionDecrypter.decrypt(ciphertext);
      fail("should fail with no key found");
    } catch (KeyczarException e) {
      // expected
    }
  }
}
