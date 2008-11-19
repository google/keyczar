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
import org.keyczar.Signer;
import org.keyczar.Verifier;
import org.keyczar.exceptions.BadVersionException;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortSignatureException;

import java.io.RandomAccessFile;
import java.nio.ByteBuffer;

/**
 * Tests Signer class for signing and verifying with HMAC, RSA, and DSA.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class SignerTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  private byte[] inputBytes = input.getBytes();

  private final void testSignerVerify(String subDir) throws Exception {
    Signer signer = new Signer(TEST_DATA + subDir);
    RandomAccessFile activeInput =
      new RandomAccessFile(TEST_DATA + subDir + "/1.out", "r");
    String activeSignature = activeInput.readLine(); 
    activeInput.close();
    RandomAccessFile primaryInput =
      new RandomAccessFile(TEST_DATA + subDir + "/2.out", "r");
    String primarySignature = primaryInput.readLine();
    primaryInput.close();

    assertTrue(signer.verify(input, activeSignature));
    assertTrue(signer.verify(input, primarySignature));
  }
  
  private final void testPublicVerify(String subDir) throws Exception {
    Verifier verifier = new Verifier(TEST_DATA + subDir);
    Verifier publicVerifier = new Verifier(TEST_DATA + subDir + ".public");
    RandomAccessFile activeInput =
      new RandomAccessFile(TEST_DATA + subDir + "/1.out", "r");
    String activeSignature = activeInput.readLine(); 
    activeInput.close();
    RandomAccessFile primaryInput =
      new RandomAccessFile(TEST_DATA + subDir + "/2.out", "r");
    String primarySignature = primaryInput.readLine();
    primaryInput.close();

    assertTrue(verifier.verify(input, activeSignature));
    assertTrue(verifier.verify(input, primarySignature));
    assertTrue(publicVerifier.verify(input, activeSignature));
    assertTrue(publicVerifier.verify(input, primarySignature));
  }

  private final void testBadVerify(String subDir) throws Exception {
    Signer signer = new Signer(TEST_DATA + subDir);
    RandomAccessFile activeInput =
      new RandomAccessFile(TEST_DATA + subDir + "/1.out", "r");
    String activeSignature = activeInput.readLine(); 
    activeInput.close();
    RandomAccessFile primaryInput =
      new RandomAccessFile(TEST_DATA + subDir + "/2.out", "r");
    String primarySignature = primaryInput.readLine();
    primaryInput.close();

    assertFalse(signer.verify("Wrong String", activeSignature));
    assertFalse(signer.verify("Wrong String", primarySignature));
    // Replace some signature bytes with junk
    assertFalse(signer.verify(input,
        primarySignature.substring(0, primarySignature.length() - 4) + "Junk"));
  }
  
  @Test
  public final void testHmacSignAndVerify() throws KeyczarException {
    Signer hmacSigner = new Signer(TEST_DATA + "/hmac");
    String sig = hmacSigner.sign(input);
    assertTrue(hmacSigner.verify(input, sig));
    System.out.println("Hmac Sig: " + sig);
    // Try signing and verifying directly in a buffer
    ByteBuffer buffer =
      ByteBuffer.allocate(inputBytes.length + hmacSigner.digestSize());
    buffer.put(inputBytes);
    ByteBuffer sigBuffer = buffer.slice();
    buffer.limit(buffer.position());
    buffer.rewind();
    hmacSigner.sign(buffer, sigBuffer);
    buffer.rewind();
    sigBuffer.rewind();
    assertTrue(hmacSigner.verify(buffer, sigBuffer));
  }

  @Test
  public final void testHmacVerify() throws Exception {
    testSignerVerify("/hmac");
  }
  
  @Test
  public final void testBadHmacVerify() throws Exception {
    testBadVerify("/hmac");
  }
  
  @Test
  public final void testDsaSignAndVerify() throws KeyczarException {
    Signer dsaSigner = new Signer(TEST_DATA + "/dsa");
    String sig = dsaSigner.sign(input);
    System.out.println("Dsa Sig: " + sig);
    assertTrue(dsaSigner.verify(input, sig));
    assertFalse(dsaSigner.verify("Wrong string", sig));
  }

  @Test
  public final void testDsaSignerVerify() throws Exception {
    testSignerVerify("/dsa");
    testPublicVerify("/dsa");
  }
  
  @Test
  public final void testBadDsaVerify() throws Exception {
    testBadVerify("/dsa");
  }
    
  @Test
  public final void testRsaSignAndVerify() throws KeyczarException {
    Signer rsaSigner = new Signer(TEST_DATA + "/rsa-sign");
    String sig = rsaSigner.sign(input);
    System.out.println("Rsa Sig: " + sig);
    assertTrue(rsaSigner.verify(input, sig));
    assertFalse(rsaSigner.verify("Wrong string", sig));
  }

  @Test
  public final void testRsaSignerVerify() throws Exception {
    testSignerVerify("/rsa-sign");
    testPublicVerify("/rsa-sign");
  }

  @Test
  public final void testBadRsaVerify() throws Exception {
    testBadVerify("/rsa-sign");
  }
  
  
  private final void testUnversionedSignAndVerify(String subDir)
      throws Exception {
    UnversionedSigner signer = new UnversionedSigner(TEST_DATA + subDir);
    byte[] sig = signer.sign(inputBytes);
    assertTrue(signer.verify(inputBytes, sig));
  }
  
  @Test
  public final void testHmacUnversionedSignAndVerify() throws Exception {
    testUnversionedSignAndVerify("/hmac");
  }
  
  @Test
  public final void testDsaUnversionedSignAndVerify() throws Exception {
    testUnversionedSignAndVerify("/dsa");
  }

  @Test
  public final void testRsaUnversionedSignAndVerify() throws Exception {
    testUnversionedSignAndVerify("/rsa-sign");
  }
  
  @Test
  public final void testHmacBadSigs() throws KeyczarException {
    Signer hmacSigner = new Signer(TEST_DATA + "/hmac");
    byte[] sig = hmacSigner.sign(inputBytes);

    // Another input string should not verify
    assertFalse(hmacSigner.verify("Some other string".getBytes(), sig));

    try {
      hmacSigner.verify(inputBytes, new byte[0]);
    } catch (ShortSignatureException e) {
      // Expected
    }
    // Munge the signature version
    sig[0] ^= 23;
    try {
      hmacSigner.verify(inputBytes, sig);
    } catch (BadVersionException e) {
      // Expected
    }
    // Reset the version
    sig[0] ^= 23;
    // Munge the key identifier
    sig[1] ^= 45;
    try {
      hmacSigner.verify(inputBytes, sig);
    } catch (KeyNotFoundException e) {
      // Expected
    }
    // Reset the key identifier
    sig[1] ^= 45;
     
  }
}