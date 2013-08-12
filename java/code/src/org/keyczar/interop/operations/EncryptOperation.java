package org.keyczar.interop.operations;

import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.exceptions.KeyczarException;

import java.util.Set;

/**
 * Tests functionality of Encryption
 */
public class EncryptOperation extends Operation {

  public EncryptOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }

  @Override
  public byte[] generate(String algorithm, Set<String> generateParams) throws KeyczarException {
    if (generateParams.contains("crypter")) {
      Crypter crypter = new Crypter(getKeyPath(algorithm));
      if (generateParams.contains("encoded")) {
        String ciphertext = crypter.encrypt(testData);
        return ciphertext.getBytes();
      } else if (generateParams.contains("unencoded")) {
        byte[] ciphertext = crypter.encrypt(testData.getBytes());
        return ciphertext;
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else if (generateParams.contains("encrypter")) {
      Encrypter crypter = new Encrypter(getKeyPath(algorithm));
      if (generateParams.contains("encoded")) {
        String ciphertext = crypter.encrypt(testData);
        return ciphertext.getBytes();
      } else if (generateParams.contains("unencoded")) {
        byte[] ciphertext = crypter.encrypt(testData.getBytes());
        return ciphertext;
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else {
      throw new KeyczarException("Expects crypter or encrypter in parameters");
    }
  }

  @Override
  public void test(
      byte[] output, String algorithm, Set<String> generateParams, Set<String> testParams)
      throws KeyczarException {
    Crypter crypter = new Crypter(getKeyPath(algorithm));
    if (generateParams.contains("encoded")) {
      String plaintext = crypter.decrypt(new String(output));
      assert(plaintext.equals(testData));
    } else if (generateParams.contains("unencoded")) {
      byte[] plaintext = crypter.decrypt(output);
      assert((new String(plaintext)).equals(testData));
    } else {
      throw new KeyczarException("Expects encoded or unencoded in parameters");
    }
  }

}
