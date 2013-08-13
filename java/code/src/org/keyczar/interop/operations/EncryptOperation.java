package org.keyczar.interop.operations;

import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.exceptions.KeyczarException;

import java.util.Map;
import java.util.Set;

/**
 * Tests functionality of Encryption
 */
public class EncryptOperation extends Operation {

  public EncryptOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }

  @Override
  public byte[] generate(String algorithm, Map<String, String> generateParams) throws KeyczarException {
    if (generateParams.get("class").equals("crypter")) {
      Crypter crypter = new Crypter(getKeyPath(algorithm));
      if (generateParams.get("encoding").equals("encoded")) {
        String ciphertext = crypter.encrypt(testData);
        return ciphertext.getBytes();
      } else if (generateParams.get("encoding").equals("unencoded")) {
        byte[] ciphertext = crypter.encrypt(testData.getBytes());
        return ciphertext;
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else if (generateParams.get("class").equals("encrypter")) {
      Encrypter crypter = new Encrypter(getKeyPath(algorithm));
      if (generateParams.get("encoding").equals("encoded")) {
        String ciphertext = crypter.encrypt(testData);
        return ciphertext.getBytes();
      } else if (generateParams.get("encoding").equals("unencoded")) {
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
      byte[] output, String algorithm, Map<String, String> generateParams, Map<String, String> testParams)
      throws KeyczarException {
    Crypter crypter = new Crypter(getKeyPath(algorithm));
    if (generateParams.get("encoding").equals("encoded")) {
      String plaintext = crypter.decrypt(new String(output));
      assert(plaintext.equals(testData));
    } else if (generateParams.get("encoding").equals("unencoded")) {
      byte[] plaintext = crypter.decrypt(output);
      assert((new String(plaintext)).equals(testData));
    } else {
      throw new KeyczarException("Expects encoded or unencoded in parameters");
    }
  }

}
