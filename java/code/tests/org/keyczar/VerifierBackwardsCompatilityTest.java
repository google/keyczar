package org.keyczar;

import java.nio.ByteBuffer;
import junit.framework.TestCase;
import org.junit.Test;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;

/**
 * This test makes sure that the verification of both proper length signatures and signatures with
 * extra bytes appended can be verified.
 */
public class VerifierBackwardsCompatilityTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private Signer privateKeySigner;
  private Verifier publicKeyVerifier;
  private byte[] data;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    privateKeySigner = new Signer(TEST_DATA + "/dsa");
    publicKeyVerifier = new Verifier(TEST_DATA + "/dsa.public");
    data = Base64Coder.decodeWebSafe(
        "U3VjY2VzcyEgWW91J3ZlIG1hbmFnZWQgdG8gaW5maWx0cmF0ZSBDb21tYW5kZXIgTGFtYmRhJ3MgZXZpbCBvcmdhbm"
        + "l6YXRpb24sIGFuZCBmaW5hbGx5IGVhcm5lZCB5b3Vyc2VsZiBhbiBlbnRyeS1sZXZlbCBwb3NpdGlvbiBhcyBhIE"
        + "1pbmlvbiBvbiBoZXIgc3BhY2Ugc3RhdGlvbi4gRnJvbSBoZXJlLCB5b3UganVzdCBtaWdodCBiZSBhYmxlIHRvIH"
        + "N1YnZlcnQgaGVyIHBsYW5zIHRvIHVzZSB0aGUgTEFNQkNIT1AgZG9vbXNkYXkgZGV2aWNlIHRvIGRlc3Ryb3kgQn"
        + "VubnkgUGxhbmV0LiBQcm9ibGVtIGlzLCBNaW5pb25zIGFyZSB0aGUgbG93ZXN0IG9mIHRoZSBsb3cgaW4gdGhlIE"
        + "xhbWJkYSBoaWVyYXJjaHkuIEJldHRlciBidWNrIHVwIGFuZCBnZXQgd29ya2luZywgb3IgeW91J2xsIG5ldmVyIG"
        + "1ha2UgaXQgdG8gdGhlIHRvcC4uLg=="
        );
  }

  @Test
  public final void testVerifyWithExtraBytes() throws KeyczarException {
    byte[] signature = privateKeySigner.sign(data);
    for (int cruftSize = 0; cruftSize < 16; cruftSize++) {
      ByteBuffer cruftySignature = ByteBuffer.allocate(signature.length + cruftSize);
      cruftySignature.put(signature);
      for (int i = 0; i < cruftSize; i++) {
        cruftySignature.put((byte)i);
      }
      assertTrue("failed with " + cruftSize + " bytes of cruft",
          publicKeyVerifier.verify(data, cruftySignature.array()));
    }
  }
}