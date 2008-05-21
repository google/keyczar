package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;

public class CrypterTest {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  private String aesActiveCiphertext = 
    "AYN36R2J9tlLZJI/ZLmV1ut9LakU24uRjU42EA3ByZwQBVt8wZNFBCK8abXY9eEV5XTewG" +
    "OrByp89SEwfEPPDfkTqlWxU2wj1Q==";

  private String aesPrimaryCiphertext =
    "AW+MRwee+oDY5/2aJPIjIEd3wzUN2INCi2d03qJhXhBlIESrX0YqJG07q0tIHD+vKXmPP0" +
    "daywsyLfhU+PwTuD46FHALh0vhfw==";

  private String rsaActiveCiphertext = 
    "AWcHdR+95JRxn9780nbMn4AfrmVmw0jPYAuocWc47ZxvEYMy7M4lm49fNFctNijwTWdqXS" +
    "DoS2itaRnQpZ3lsh11RRmD3NeSeX+bA5DBF7tL5mhmfYcGi2Ba1VG/ViEN3m4SO30BWMss" +
    "QeXr82fIjaAuoUP/fN3IYi74sxMiAV5dE6WZgB3C/wx1aDmojP75CwoU5AT7lIpsQfy1Y7" +
    "ELp26DCprhkVsMSnyjzGKNErCeA+5V8Pvn7CXEDpko/s12U3nCoFx740QG6z7Q/MuHGS3k" +
    "cLiclOpzYDrkt7zwDRDsCRNr2Dp2Siqy6ko2JC4EKpOTPdm+1/SF3srPzujtZ50DVEns";
  private String rsaPrimaryCiphertext = 
    "AYwJyHs8a+pDHgQrr/SKcg5nbW4e5TekDxOgBWwzBGgOZvhTCUbzFk4tDaWgBAG4F+JQzL" +
    "Nl12FPQBLS0Yw0PN1xvUH+2PE8DBYUWVgeqFumTskYtb9z/3KIGjrYkblL+TQSxEZ3gOpi" +
    "W1ygGe9XU59K2IlHdZiOiK3fhkeby6V0coRUvdJKGCvVjXaH0KDdJQdoT8zve44uW4M3FR" +
    "bnmM9vwwpt2XUxr5gC6bdr2nIAX7vMLEMDluvvzvroDZKaEYxtF1sUl2Fao53pqT3bZ/19" +
    "CN7v0vLu8LCpHKjLhNmpGeqWcp9kzeqE520BVsnJNW7XAbJs7sTplbW9F7zM/0eHiw0v";
  
  @Test
  public final void testRsaEncryptAndDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/rsa");
    String ciphertext = crypter.encrypt(input);
    System.out.println("Rsa Ciphertext: " + ciphertext);
    String decrypted = crypter.decrypt(ciphertext);
    assertEquals(input, decrypted);
  }
  
  @Test
  public final void testRsaDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/rsa");
    String activeDecrypted = crypter.decrypt(rsaActiveCiphertext);
    assertEquals(input, activeDecrypted);
    String primaryDecrypted = crypter.decrypt(rsaPrimaryCiphertext);
    assertEquals(input, primaryDecrypted);
  }
  
  @Test
  public final void testAesEncryptAndDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    String ciphertext = crypter.encrypt(input);
    System.out.println("Aes Ciphertext: " + ciphertext);
    String decrypted = crypter.decrypt(ciphertext);
    assertEquals(input, decrypted);
  }
  
  @Test
  public final void testAesDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    String decryptedActive = crypter.decrypt(aesActiveCiphertext);
    assertEquals(input, decryptedActive);
    String decryptedPrimary = crypter.decrypt(aesPrimaryCiphertext);
    assertEquals(input, decryptedPrimary);
  }
  
  @Test
  public final void testBadAesCiphertexts() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    try {
      byte[] decrypted = crypter.decrypt(new byte[0]);
    } catch (ShortCiphertextException e) {
      // Expected exception
    }
    byte[] ciphertext = crypter.encrypt(input.getBytes());
    // Munge the ciphertext
    ciphertext[1] ^= 44;
    try {
      byte[] decrypted = crypter.decrypt(ciphertext);
    } catch (KeyNotFoundException e) {
      // Expected exception
    }    
  }
}
