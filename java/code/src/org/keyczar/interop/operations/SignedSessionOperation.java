package org.keyczar.interop.operations;

import com.google.gson.Gson;

import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.SignedSessionDecrypter;
import org.keyczar.SignedSessionEncrypter;
import org.keyczar.Signer;
import org.keyczar.Verifier;
import org.keyczar.exceptions.Base64DecodingException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;

import java.util.Map;

/**
 * Tests functionality of signed sessions
 */
public class SignedSessionOperation extends Operation {

  public SignedSessionOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }

  @Override
  public byte[] generate(String algorithm, Map<String, String> generateParams)
      throws KeyczarException {
    Encrypter keyEncrypter = new Encrypter(getKeyPath(algorithm));
    Signer signer = new Signer(getKeyPath(generateParams.get("signer")));
    SignedSessionEncrypter crypter = new SignedSessionEncrypter(keyEncrypter, signer);
    String sessionMaterial = crypter.newSession();
    byte[] ciphertext = crypter.encrypt(testData.getBytes());
    
    Gson gson = new Gson();
    String output = gson.toJson(new SignedSessionOutput(ciphertext, sessionMaterial));
    return output.getBytes();
  }

  @Override
  public void test(
      byte[] output, String algorithm, Map<String, String> generateParams,
      Map<String, String> testParams) throws KeyczarException {
    Gson gson = new Gson();
    SignedSessionOutput out = gson.fromJson(new String(output), SignedSessionOutput.class);
    byte[] encryptedData = Base64Coder.decodeWebSafe(out.output);
    String sessionMaterial = out.sessionMaterial;
    
    Crypter keyCrypter = new Crypter(getKeyPath(algorithm));
    Verifier verifier = new Verifier(getKeyPath(generateParams.get("signer")));
    SignedSessionDecrypter sessionCrypter =
        new SignedSessionDecrypter(keyCrypter, verifier, sessionMaterial);
    byte[] decryptedData = sessionCrypter.decrypt(encryptedData);
    assert(new String(decryptedData).equals(testData));

  }
  
  /**
   * Used for the gson representation of signed sessions
   */
  static class SignedSessionOutput {
    public final String output;
    public final String sessionMaterial;

    public SignedSessionOutput(byte[] output, String sessionMaterial) {
      this.output = Base64Coder.encodeWebSafe(output);
      this.sessionMaterial = sessionMaterial;
    }
  }
  
  @Override
  public String formatOutput(byte[] output){
    return new String(output);
  }
  
  @Override
  public byte[] readOutput(String output) throws Base64DecodingException{
    return output.getBytes();
  }
  
  

}
