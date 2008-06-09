/*
 * Copyright 2008 Google Inc.
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

package com.google.keyczar.enums;

import com.google.gson.annotations.Expose;

// TODO: Write JavaDocs
public enum KeyType {
  AES(0, 128, 0), DSA_PRIV(2, 1024, 48), DSA_PUB(3, 1024, 48), HMAC_SHA1(1,
      256, 20), RSA_PRIV(4, 2048, 256), RSA_PUB(5, 2048, 256), TEST(127, 1, 0);

  private int defaultSize;
  private int outputSize;
  @Expose
  private int value;

  private KeyType(int v, int defaultSize, int outputSize) {
    value = v;
    this.defaultSize = defaultSize;
    this.outputSize = outputSize;
  }

  // Returns default size in bits
  public int defaultSize() {
    return defaultSize;
  }

  public int getOutputSize() {
    return outputSize;
  }

  int getValue() {
    return value;
  }

  static KeyType getType(int value) {
    switch (value) {
    case 0:
      return AES;
    case 1:
      return HMAC_SHA1;
    case 2:
      return DSA_PRIV;
    case 3:
      return DSA_PUB;
    case 4:
      return DSA_PRIV;
    case 5:
      return DSA_PUB;
    case 127:
      return TEST;
    }
    return null;
  }
}
