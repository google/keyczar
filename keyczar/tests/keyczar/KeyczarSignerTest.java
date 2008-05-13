package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

public class KeyczarSignerTest {
  private static final String TEST_DATA = "./testdata";
  private KeyczarSigner signer;
  private byte[] input = "This is some test input".getBytes();
  
  // This is a signature on 'input' by the primary key (version 2)
  private byte[] primarySig = {1, -53, -70, -13, 105, -2, -82, -40, 8, -99,
      -85, -28, 46, 89, -128, 73, -87, -122, 121, -38, -8, -107, 6, -25, 15};

  // This is a signature on 'input' by an active key (version 1)
  private byte[] activeSig = {1, 10, -119, 63, -127, -9, 71, -111, -100, 29,
      -128, -119, -70, 98, -90, -90, -116, 33, -33, -27, 42, -85, 60, -65, 82};

  @Before
  public void setUp() throws Exception {
    signer = new KeyczarSigner(TEST_DATA + "/hmac");
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
