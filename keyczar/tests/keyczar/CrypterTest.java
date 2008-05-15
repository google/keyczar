package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;

public class CrypterTest {
  private static final String TEST_DATA = "./testdata";
  private Crypter crypter;
  private byte[] input = "This is some test input".getBytes();
  private byte[] activeAesCiphertext = {1, 108, -22, 89, 71, 29, 67, 73, 56,
      -78, 8, 102, 114, -128, 89, -66, 3, 48, 23, -69, -127, -15, -34, -32,
      -55, 111, 115, 2, 81, 16, 2, 116, -28, -7, 40, -121, -55, -12, 81, 58,
      55, -86, 29, -21, -124, -48, -20, 6, -123, 117, 43, -10, 4, -97, 83, -49,
      -92, 64, 1, 112, -54, -46, -114, -88, -102, -51, -121, -11, 89, 57, -120,
      88, -15};
  
  private byte[] primaryAesCiphertext = {1, 81, -80, 65, 125, 31, 60, -110,
      -39, -28, -128, -35, 41, -6, -10, 60, -98, 77, 35, 119, 117, 13, -13,
      78, 50, 24, 39, -43, -76, -6, -42, -119, -59, -60, -2, 114, 80, 65,
      -12, -53, -58, -40, -25, 120, 76, 82, 34, 96, -115, 16, -43, 74, -17,
      -103, 103, -52, -69, 94, -4, -28, -7, -97, -76, -114, -1, -88, 70, -86,
      -25, -65, 103, -84, -53 };

  @Before
  public void setUp() throws Exception {
    crypter = new Crypter(TEST_DATA + "/aes");
  }

  @Test
  public final void testEncryptAndDecrypt() throws KeyczarException {
    byte[] ciphertext = crypter.encrypt(input);
    byte[] decrypted = crypter.decrypt(ciphertext);
    assertArrayEquals(input, decrypted);
  }
  
  @Test
  public final void testDecrypt() throws KeyczarException {
    byte[] activeDecrypted = crypter.decrypt(activeAesCiphertext);
    assertArrayEquals(input, activeDecrypted);
    byte[] primaryDecrypted = crypter.decrypt(primaryAesCiphertext);
    assertArrayEquals(input, primaryDecrypted);
  }
  
  @Test
  public final void testBadCiphertexts() throws KeyczarException {
    try {
      byte[] decrypted = crypter.decrypt(new byte[0]);
    } catch (ShortCiphertextException e) {
      // Expected exception
    }
    // Munge the ciphertext
    activeAesCiphertext[1] ^= 44;
    try {
      byte[] decrypted = crypter.decrypt(activeAesCiphertext);
    } catch (KeyNotFoundException e) {
      // Expected exception
    }
    activeAesCiphertext[1] ^= 44;

    
  }
}
