package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;

public class KeyczarSignerTest {
  private static final String TEST_DATA = "./testdata";
  private KeyczarSigner signer = new KeyczarSigner(TEST_DATA + "/hmac");
  private byte[] input = "This is some test input".getBytes();
  
  // This is a signature on 'input' by the primary key (version 2)
  private byte[] primarySig = {1, -53, -70, -13, 105, -2, -82, -40, 8, -99,
      -85, -28, 46, 89, -128, 73, -87, -122, 121, -38, -8, -107, 6, -25, 15};

  // This is a signature on 'input' by an active key (version 1)
  private byte[] activeSig = {1, 10, -119, 63, -127, -9, 71, -111, -100, 29,
      -128, -119, -70, 98, -90, -90, -116, 33, -33, -27, 42, -85, 60, -65, 82};

  @Before
  public void setUp() throws Exception {
    signer.read();
  }

  @Test
  public final void testSignAndVerify() throws KeyczarException,
      GeneralSecurityException {
    byte[] sig = signer.sign(input);
    assertTrue(signer.verify(input, sig));
  }
  
  public final void testVerify() throws KeyczarException,
      GeneralSecurityException {
    byte[] sig = signer.sign(input);
    assertEquals(sig, primarySig);
    assertTrue(signer.verify(input, primarySig));
    assertTrue(signer.verify(input, activeSig));
  }

  @Test
  public final void testBadSigs() throws KeyczarException,
      GeneralSecurityException {
    byte[] sig = signer.sign(input);
    assertEquals(signer.verify(input, new byte[0]), false);
    assertEquals(signer.verify(input, 0, input.length, new byte[0], 0),
        KeyczarVerifier.VerifyResult.MALFORMED);
    // Munge the key identifier
    sig[1] ^= 45;
    assertEquals(signer.verify(input, sig), false);
    assertEquals(signer.verify(input, 0, input.length, sig, 0),
        KeyczarVerifier.VerifyResult.KEY_UNAVAILABLE);
    // Reset the key identifier
    sig[1] ^= 45;
    
    assertEquals(signer.verify("Some other string".getBytes(), sig), false);
    assertEquals(signer.verify(input, 0, input.length, sig, 5),
        KeyczarVerifier.VerifyResult.MALFORMED);
  }

}
