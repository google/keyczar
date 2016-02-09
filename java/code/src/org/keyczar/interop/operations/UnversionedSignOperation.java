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

import org.keyczar.UnversionedSigner;
import org.keyczar.UnversionedVerifier;
import org.keyczar.exceptions.KeyczarException;

import java.util.Map;

/**
 * Tests functionality of unversioned signing
 */
public class UnversionedSignOperation extends Operation {

  public UnversionedSignOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }
  
  @Override
  public byte[] generate(String algorithm, Map<String, String> generateParams)
      throws KeyczarException{
    UnversionedSigner signer = new UnversionedSigner(
        getReader(algorithm, generateParams.get("cryptedKeySet"), ""));
    if (generateParams.get("encoding").equals("encoded")) {
      String signature = signer.sign(testData);
      return signature.getBytes();
    } else if (generateParams.get("encoding").equals("unencoded")) {
      byte[] signature = signer.sign(testData.getBytes());
      return signature;
    } else {
      throw new KeyczarException("Expects encoded or unencoded in parameters");
    }
  }

  @Override
  public void test(
      Map<String, String> output, String algorithm, Map<String, String> generateParams,
      Map<String, String> testParams) throws KeyczarException {
    if (testParams.get("class").equals("signer")) {
      UnversionedSigner verifier = new UnversionedSigner(
          getReader(algorithm, generateParams.get("cryptedKeySet"), testParams.get("pubKey")));
      if (generateParams.get("encoding").equals("encoded")) {
        assert(verifier.verify(testData, new String(readOutput(output))));
      } else if (generateParams.get("encoding").equals("unencoded")) {
        assert(verifier.verify(testData.getBytes(), readOutput(output)));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else if (testParams.get("class").equals("verifier")) {
      UnversionedVerifier verifier = new UnversionedVerifier(
          getReader(algorithm, generateParams.get("cryptedKeySet"), testParams.get("pubKey")));
      if (generateParams.get("encoding").equals("encoded")) {
        assert(verifier.verify(testData, new String(readOutput(output))));
      } else if (generateParams.get("encoding").equals("unencoded")) {
        assert(verifier.verify(testData.getBytes(), readOutput(output)));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else {
      throw new KeyczarException("Expects signer or verifier in parameters");
    }  
  }

}
