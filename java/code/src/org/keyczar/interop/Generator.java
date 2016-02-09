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

package org.keyczar.interop;

import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interop.operations.Operation;
import org.keyczar.util.Util;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Class used for gson data to call generate commands
 */
public class Generator {
  @SuppressWarnings("unused")
  private final String command;
  private final String operation;
  private final String keyPath;
  private final String algorithm;
  private final Map<String, String> generateOptions;
  private final String testData;
  
  private Generator(
      String command, String operation, String keyPath, 
      String algorithm, Map<String, String> generateOptions, String testData) {
    this.command = command;
    this.operation = operation;
    this.keyPath = keyPath;
    this.algorithm = algorithm;
    this.generateOptions = generateOptions;
    this.testData = testData;
  }
  
  
  public String generate() throws KeyczarException {
    Operation op = Operation.getOperationByName(operation, keyPath, testData);
    byte[] output = op.generate(algorithm, generateOptions);
    return op.formatOutput(output);
  }

  static Generator read(String jsonString) {
    try {
      JSONObject json = new JSONObject(jsonString);
    return new Generator(
        json.optString("command"),
        json.optString("operation"),
        json.optString("keyPath"),
        json.optString("algorithm"),
        Util.deserializeMap(json.optJSONObject("generateOptions")),
        json.optString("testData"));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }
}
