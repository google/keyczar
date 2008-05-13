package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;

public class KeyczarCrypterTest {
  private static final String TEST_DATA = "./testdata";
  private KeyczarCrypter crypter;
  private byte[] input = "This is some test input".getBytes();
  private byte[] aesCiphertext = {1, -44, 110, -60, 25, 89, -43, -127, 60, 89,
      11, -96, -94, 78, -126, 23, -94, 55, -81, -80, 105, -65, 4, -28, -77,
      -125, -116, -83, -81, 103, 121, 108, -47, -66, 114, 26, 92, 35, 61, 26,
      33, 26, -76, -81, -121, 122, 73, -48, -31, -62, 100, -90, -15, 43, -120,
      89, 32, -4, -64, 42, -107, -13, -67, -29, -124, -31, 70, -65, -25, -24,
      -56, -44, -74};

  @Before
  public void setUp() throws Exception {
    crypter = new KeyczarCrypter(TEST_DATA + "/aes");
  }

  @Test
  public final void testEncryptAndDecrypt() throws KeyczarException {
    byte[] ciphertext = crypter.encrypt(input);
    byte[] decrypted = crypter.decrypt(ciphertext);
    assertArrayEquals(input, decrypted);
  }
  
  @Test
  public final void testDecrypt() throws KeyczarException {
    byte[] decrypted = crypter.decrypt(aesCiphertext);
    assertArrayEquals(input, decrypted);
  }
  
  @Test
  public final void testBadCiphertexts() throws KeyczarException {
    try {
      byte[] decrypted = crypter.decrypt(new byte[0]);
    } catch (ShortCiphertextException e) {
      // Expected exception
    }
    
  }
}
