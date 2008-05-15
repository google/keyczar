package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

public class SignerTest {
  private static final String TEST_DATA = "./testdata";
  private Signer signer;
  private byte[] input = "This is some test input".getBytes();
  
  // This is a signature on 'input' by the primary key (version 2)
  private byte[] primarySig = {1, 88, -7, 7, -105, -99, -49, 66, 97, -47, -36,
      72, -13, 8, -123, 56, -74, 4, -118, 36, 18, 92, 25, 39, -84};

  // This is a signature on 'input' by an active key (version 1)
  private byte[] activeSig = {1, -105, -3, 86, 29, -80, 11, 114, -27, 49, -118,
      104, 98, -38, -59, 106, 31, 42, 41, 122, -71, -6, 116, 14, 62};

  @Before
  public void setUp() throws Exception {
    signer = new Signer(TEST_DATA + "/hmac");
  }

  @Test
  public final void testSignAndVerify() throws KeyczarException {
    byte[] sig = signer.sign(input);
    assertArrayEquals(sig, primarySig);
    assertTrue(signer.verify(input, sig));
    
    // Try signing and verifying directly in a buffer
    ByteBuffer buffer = ByteBuffer.allocate(input.length + signer.digestSize());
    buffer.put(input);
    ByteBuffer sigBuffer = buffer.slice();
    buffer.limit(buffer.position());
    buffer.rewind();
    signer.sign(buffer, sigBuffer);
    buffer.rewind();
    sigBuffer.rewind();
    assertTrue(signer.verify(buffer, sigBuffer));
  }

  @Test
  public final void testVerify() throws KeyczarException {
    byte[] sig = signer.sign(input);
    assertArrayEquals(sig, primarySig);
    assertTrue(signer.verify(input, primarySig));
    assertTrue(signer.verify(input, activeSig));
    
    ByteBuffer buffer = ByteBuffer.allocate(input.length + signer.digestSize());
    buffer.put(input);
    ByteBuffer sigBuffer = buffer.slice();
    buffer.limit(buffer.position());
    buffer.rewind();
    sigBuffer.put(primarySig);
    sigBuffer.rewind();
    assertTrue(signer.verify(buffer, sigBuffer));
  }

  @Test
  public final void testBadSigs() throws KeyczarException {
    byte[] sig = signer.sign(input);

    // Another input string should not verify
    assertFalse(signer.verify("Some other string".getBytes(), sig));

    try {
      signer.verify(input, new byte[0]);
    } catch (ShortSignatureException e) {
      // Expected
    }
    // Munge the signature version
    sig[0] ^= 23;
    try {
      signer.verify(input, sig);
    } catch (BadVersionException e) {
      // Expected
    }
    // Reset the version
    sig[0] ^= 23;
    // Munge the key identifier
    sig[1] ^= 45;
    try {
      signer.verify(input, sig);
    } catch (KeyNotFoundException e) {
      // Expected
    }
    // Reset the key identifier
    sig[1] ^= 45;
     
  }

}
