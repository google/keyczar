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

import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.exceptions.KeyczarException;

import java.util.Map;

/**
 * Tests functionality of Encryption
 */
public class EncryptOperation extends Operation {

  public EncryptOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }

  @Override
  public byte[] generate(String algorithm, Map<String, String> generateParams)
      throws KeyczarException {
    if (generateParams.get("class").equals("crypter")) {
      Crypter crypter = new Crypter(
          getReader(algorithm, generateParams.get("cryptedKeySet"), generateParams.get("pubKey")));
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
      Encrypter crypter = new Encrypter(
          getReader(algorithm, generateParams.get("cryptedKeySet"), generateParams.get("pubKey")));
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
      Map<String, String> output, String algorithm, Map<String, String> generateParams,
      Map<String, String> testParams) throws KeyczarException {
    Crypter crypter = new Crypter(
        getReader(algorithm, generateParams.get("cryptedKeySet"), ""));
    if (generateParams.get("encoding").equals("encoded")) {
      String plaintext = crypter.decrypt(new String(readOutput(output)));
      assert(plaintext.equals(testData));
    } else if (generateParams.get("encoding").equals("unencoded")) {
      byte[] plaintext = crypter.decrypt(readOutput(output));
      assert((new String(plaintext)).equals(testData));
    } else {
      throw new KeyczarException("Expects encoded or unencoded in parameters");
    }
  }

}
