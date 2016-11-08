package org.keyczar;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import junit.framework.TestCase;
import org.junit.Test;
import org.keyczar.exceptions.KeyczarException;

/**
 * This test makes sure that the verification of both proper length signatures and signatures with
 * extra bytes appended can be verified.
 */
public class VerifierBackwardsCompatilityTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private Signer privateKeySigner;
  private Verifier publicKeyVerifier;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    privateKeySigner = new Signer(TEST_DATA + "/dsa");
    publicKeyVerifier = new Verifier(TEST_DATA + "/dsa.public");
  }

  @Test
  public final void testVariableLengthSignaturesWithExtraBytes() throws KeyczarException {
    // This is (I'm so sorry) a random test - because the signing process includes a random element.
    // However, generally all these three sizes are found quite quickly, so this should not be too
    // slow, nor flaky (if it flakes, buy a lottery ticket, and yell at me).
    Set<Integer> remainingSizes = new HashSet<Integer>();
    remainingSizes.add(50);
    remainingSizes.add(51);
    remainingSizes.add(52);

    int limit = 10000;
    Boolean jceDoesStrictVerification = null;
    for (int i = 0; i < limit; i++) {
      byte[] plaintext = BigInteger.valueOf(i).toByteArray();
      byte[] signature = privateKeySigner.sign(plaintext);
      int signatureSize = signature.length;
      // Is this is a size that still needs to be tested
      if (remainingSizes.contains(signatureSize)) {
        for (int totalLength = signatureSize; totalLength <= 52; totalLength++) {
          String error = "for " + i + ":" + signatureSize + ":" + totalLength;
          byte[] signatureWithExtraBytes = new byte[totalLength];
          System.arraycopy(signature, 0, signatureWithExtraBytes, 0, signature.length);
          int extraBytesLength = totalLength - signature.length;

          // Start by testing without strict verification - even with extra bytes at the end,
          // the signatures should verify.
          DsaPublicKey.setStrictVerificationForTest(false);
          assertTrue("Invalid signature without strict verification " + error,
              publicKeyVerifier.verify(plaintext, signatureWithExtraBytes));

          // Now test without keyzar stripping the extra bytes.
          DsaPublicKey.setStrictVerificationForTest(true);

          // If there is no extra bytes, the signaure should verify
          if (extraBytesLength == 0) {
            assertTrue("Invalid signature with strict verification " + error,
                publicKeyVerifier.verify(plaintext, signatureWithExtraBytes));
          } else {
            // This is dependant on the behavior of the JCE - so the first time through, use the
            // behavior to decide whether the JCE has strict DSA verification - and then after that
            // require that the behavior stays the same
            boolean jceStrictVerificationDemonstrated =
                !publicKeyVerifier.verify(plaintext, signatureWithExtraBytes);
            if (jceDoesStrictVerification == null) {
              jceDoesStrictVerification = jceStrictVerificationDemonstrated;
              System.err.println("JCE strict DSA verification : " + jceDoesStrictVerification);
            } else {
              assertEquals("Invalid signature with strict verification " + error,
                  jceStrictVerificationDemonstrated, jceDoesStrictVerification.booleanValue());
            }
          }
        }

        // Have we checked all the sizes we need to check - if so, stop
        remainingSizes.remove(signatureSize);
        if (remainingSizes.isEmpty()) {
          return;
        }
      }
    }
    // If we goes here, buy a lottery ticket because you're doing some crazy odds today.
    fail("Failed after " + limit + " attempts to get 3 different signature sizes");
  }
}

