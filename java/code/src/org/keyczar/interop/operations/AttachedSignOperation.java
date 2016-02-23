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

import org.keyczar.Signer;
import org.keyczar.Verifier;
import org.keyczar.exceptions.KeyczarException;

import java.util.Map;

/**
 * Tests functionality of attached signing
 */
public class AttachedSignOperation extends Operation {

  public AttachedSignOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }

  @Override
  public byte[] generate(String algorithm, Map<String, String> generateParams)
      throws KeyczarException {
    Signer signer = new Signer(getReader(algorithm, generateParams.get("cryptedKeySet"), ""));
    if (generateParams.get("encoding").equals("encoded")) {
      // String signature = signer.attachedSign(testData, "".getBytes());
      // Not implemented
      return "".getBytes();
    } else if (generateParams.get("encoding").equals("unencoded")) {
      byte[] signature = signer.attachedSign(testData.getBytes(), "".getBytes());
      return signature;
    } else {
      throw new KeyczarException("Expects encoded or unencoded in parameters");
    }
  }

  @Override
  public void test(
      Map<String, String> output, String algorithm, 
      Map<String, String> generateParams, Map<String, String> testParams)
      throws KeyczarException {
    if (testParams.get("class").equals("signer")) {
      Signer verifier = new Signer(
          getReader(algorithm, generateParams.get("cryptedKeySet"), testParams.get("pubKey")));
      if (generateParams.get("encoding").equals("encoded")) {
        throw new KeyczarException("Not Implemented");
      } else if (generateParams.get("encoding").equals("unencoded")) {
        assert(verifier.attachedVerify(readOutput(output), "".getBytes()));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else if (testParams.get("class").equals("verifier")) {
      Verifier verifier = new Verifier(
          getReader(algorithm, generateParams.get("cryptedKeySet"), testParams.get("pubKey")));
      if (generateParams.get("encoding").equals("encoded")) {
        throw new KeyczarException("Not Implemented");
      } else if (generateParams.get("encoding").equals("unencoded")) {
        assert(verifier.attachedVerify(readOutput(output), "".getBytes()));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else {
      throw new KeyczarException("Expects signer or verifier in parameters");
    }
  }
}
