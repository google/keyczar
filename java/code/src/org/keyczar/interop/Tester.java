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

import java.util.Map;

/**
 * Class used for gson data to call test commands
 */
public class Tester {
  @SuppressWarnings("unused")
  private final String command;
  private final String operation;
  private final String keyPath;
  private final String algorithm;
  private final Map<String, String> generateOptions;
  private final Map<String, String> testOptions;
  private final Map<String, String> output;
  private final String testData;

  public Tester(
      String command, String operation, String keyPath, String algorithm, 
      Map<String, String> generateOptions, Map<String, String> testOptions,
      Map<String, String> output, String testData) {
    this.command = command;
    this.operation = operation;
    this.keyPath = keyPath;
    this.algorithm = algorithm;
    this.generateOptions = generateOptions;
    this.testOptions = testOptions;
    this.output = output;
    this.testData = testData;
  }

  public void test() throws KeyczarException {
    Operation op = Operation.getOperationByName(operation, keyPath, testData);
    op.test(output, algorithm, generateOptions, testOptions);
  }

  static Tester read(String jsonString) {
    try {
      JSONObject json = new JSONObject(jsonString);
      return new Tester(
          json.optString("command"),
          json.optString("operation"),
          json.optString("keyPath"),
          json.optString("algorithm"),
          Util.deserializeMap(json.optJSONObject("generateOptions")),
          Util.deserializeMap(json.optJSONObject("testOptions")),
          Util.deserializeMap(json.optJSONObject("output")),
          json.optString("testData"));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }
}
