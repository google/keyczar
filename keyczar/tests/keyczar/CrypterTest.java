package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;

public class CrypterTest {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";
  private String aesActiveCiphertext = 
    "AdNDEvSTDcbWSRYe/iCRsOUFcP1yMI7N4N9/U8bs0MszYBztsV83CR8BRdO6VGzI+hE" + 
    "GB5bVkY1AfPv5GXqVgEz60K0YJ/Y+uA==";
  private String aesPrimaryCiphertext =
    "ATPkV+i5x6Uvf37hDRssE1YkZVtRbs1LFkLCElkAQYDRC7s6nlM43FY9eSaWDzs+jJLu" +
    "8+qmvi6GFv5nY1mUXohbdrbdzD3Aeg==";

  @Test
  public final void testEncryptAndDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    String ciphertext = crypter.encrypt(input);
    System.out.println("Aes Ciphertext: " + ciphertext);
    String decrypted = crypter.decrypt(ciphertext);
    assertEquals(input, decrypted);
  }
  
  @Test
  public final void testDecrypt() throws KeyczarException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    String decryptedActive = crypter.decrypt(aesActiveCiphertext);
    assertEquals(input, decryptedActive);
    String decryptedPrimary = crypter.decrypt(aesPrimaryCiphertext);
    assertEquals(input, decryptedPrimary);
  }
  
  @Test
  public final void testBadCiphertexts() throws KeyczarException {
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
