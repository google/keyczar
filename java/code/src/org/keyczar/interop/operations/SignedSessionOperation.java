/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keyczar.interop.operations;

import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.SignedSessionDecrypter;
import org.keyczar.SignedSessionEncrypter;
import org.keyczar.Signer;
import org.keyczar.Verifier;
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
    Encrypter keyEncrypter = new Encrypter(
        getReader(algorithm, generateParams.get("cryptedKeySet"), generateParams.get("pubKey")));
    Signer signer = new Signer(getReader(
        generateParams.get("signer"), generateParams.get("cryptedKeySet"), ""));
    SignedSessionEncrypter crypter = new SignedSessionEncrypter(keyEncrypter, signer);
    String sessionMaterial = crypter.newSession();
    byte[] ciphertext = crypter.encrypt(testData.getBytes());

    String output = new SignedSessionOutput(ciphertext, sessionMaterial).toString();
    return output.getBytes();
  }

  @Override
  public void test(
      Map<String, String> output, String algorithm, Map<String, String> generateParams,
      Map<String, String> testParams) throws KeyczarException {
    byte[] encryptedData = readOutput(output);
    String sessionMaterial = output.get("sessionMaterial");

    Crypter keyCrypter = new Crypter(
        getReader(algorithm, generateParams.get("cryptedKeySet"), testParams.get("pubKey")));
    Verifier verifier = new Verifier(getReader(
        generateParams.get("signer"), generateParams.get("cryptedKeySet"), ""));
    SignedSessionDecrypter sessionCrypter =
        new SignedSessionDecrypter(keyCrypter, verifier, sessionMaterial);
    byte[] decryptedData = sessionCrypter.decrypt(encryptedData);
    assert(new String(decryptedData).equals(testData));

  }

  /**
   * Used for the json representation of signed sessions
   */
  static class SignedSessionOutput {
    public final String output;
    public final String sessionMaterial;

    public SignedSessionOutput(byte[] output, String sessionMaterial) {
      this.output = Base64Coder.encodeWebSafe(output);
      this.sessionMaterial = sessionMaterial;
    }

    @Override
    public String toString() {
      try {
        return new JSONObject()
            .put("output", output)
            .put("sessionMaterial", sessionMaterial)
            .toString();
      } catch (JSONException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public String formatOutput(byte[] output){
    return new String(output);
  }
}
