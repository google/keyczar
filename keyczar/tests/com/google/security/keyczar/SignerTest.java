package com.google.security.keyczar;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.keyczar.Signer;
import com.google.keyczar.Verifier;
import com.google.keyczar.exceptions.BadVersionException;
import com.google.keyczar.exceptions.KeyNotFoundException;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.exceptions.ShortSignatureException;

import org.junit.Test;

import java.nio.ByteBuffer;

public class SignerTest {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test input";
  private byte[] inputBytes = input.getBytes();
  
  // This is a signature on 'input' by the primary key (version 2)
  private String hmacPrimarySig = "Ab1PQ5IXUGHSnqcRGCLopEwt8KTdj-qw6g";

  // This is a signature on 'input' by an active key (version 1)
  private String hmacActiveSig = "AeM3GRZPlBcQRB_gJo49PLN0BwCWQ7X2rA";

  private String dsaPrimarySig = 
    "AQ2qMEQwLAIUZAqjq2J8FmIsqVttuLFmd87PfIUCFA7lCbmrh4njJKFog83E-OfuCIeK";

  private String dsaActiveSig = 
    "AdARpvYwLAIUP4P3b-y-kjKyGk1uXDvn4R5T7w8CFHDVGFMmUlDwZTtLsPrBFOis6Ktz";
  
  private String dsaCorruptSig = 
    "AdARpvYwLAIUP4P3b-y-kjKyGk1uXDvn4R5T7w8CFHDVGFMmUlDwZTtLsPrBFOis6Ktw";

  private String rsaSignature = 
    "AZjGkthszRhei7s8Ah4cCo5uzkKYwgzxuflTC_TofyD8htOVVBLLqDhhWxG9dhIRCH" +
    "DxmqUPCRO_U2uOCZkEY5aBAGMzR7fAIJ01C-Ug9705R-DY_yBb8sTBS_IcxOs6txkz" +
    "97LtpSLGjz8B22bPVriDY3WDs05xKZ4-XNIudMVITZ-iIXC-xCcwzjwzPrxjIm4OBc" +
    "x0TnP0E1o-KCaMWomrWgyrKYQrKruQHngX4Z7X8HyhfCweJcn87OiL9rzpRwCxfbS4" +
    "0-CHtSR1Z-10URqRmMya56hlFAYv3a0QpjVOYu2liuu76sU9de8wHPkV7-HRQD1UcH" +
    "lVFoBjHNcAfo3v1v6J";

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
  public final void testDsaSignAndVerify() throws KeyczarException {
    Signer dsaSigner = new Signer(TEST_DATA + "/dsa");
    String sig = dsaSigner.sign(input);
    System.out.println("Dsa Sig: " + sig);
    assertTrue(dsaSigner.verify(input, sig));
    assertFalse(dsaSigner.verify("Wrong string", sig));
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
  public final void testRsaVerify() throws KeyczarException {
    // Verify as a Signer object
    Signer rsaSigner = new Signer(TEST_DATA + "/rsa-sign");
    assertTrue(rsaSigner.verify(input, rsaSignature));
    
    // Try verifying with just the public keys
    Verifier rsaVerifier = new Verifier(TEST_DATA + "/rsa-sign.public");
    assertTrue(rsaVerifier.verify(input, rsaSignature));

    // Verify as a Verifier object
    Verifier rsaVerifier2 = new Signer(TEST_DATA + "/rsa-sign");
    assertTrue(rsaVerifier2.verify(input, rsaSignature));

  }


  @Test
  public final void testDsaVerify() throws KeyczarException {
    // Verify as a Signer object
    Signer dsaSigner = new Signer(TEST_DATA + "/dsa");
    assertTrue(dsaSigner.verify(input, dsaPrimarySig));
    assertTrue(dsaSigner.verify(input, dsaActiveSig));
        
    // Try verifying with just the public keys
    Verifier dsaVerifier = new Verifier(TEST_DATA + "/dsa.public");
    assertTrue(dsaVerifier.verify(input, dsaPrimarySig));
    assertTrue(dsaVerifier.verify(input, dsaActiveSig));
    
    // Verify as a Verifier object
    Verifier dsaVerifier2 = new Signer(TEST_DATA + "/dsa");
    assertTrue(dsaVerifier2.verify(input, dsaPrimarySig));
    assertTrue(dsaVerifier2.verify(input, dsaActiveSig));
  }
    
  @Test
  public final void testDsaBadVerify() throws KeyczarException {
    Signer dsaSigner = new Signer(TEST_DATA + "/dsa");
    assertFalse(dsaSigner.verify("Wrong string", dsaPrimarySig));
    assertFalse(dsaSigner.verify("Wrong string", dsaActiveSig));
    assertFalse(dsaSigner.verify(input, dsaCorruptSig));
  }

  @Test
  public final void testHmacVerify() throws KeyczarException {
    Signer hmacSigner = new Signer(TEST_DATA + "/hmac");
    String sig = hmacSigner.sign(input);
    assertEquals(sig, hmacPrimarySig);
    assertTrue(hmacSigner.verify(input, hmacPrimarySig));
    assertTrue(hmacSigner.verify(input, hmacActiveSig));
    
    Verifier hmacVerifier = new Signer(TEST_DATA + "/hmac");
    assertTrue(hmacVerifier.verify(input, hmacPrimarySig));
    assertTrue(hmacVerifier.verify(input, hmacActiveSig));
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
