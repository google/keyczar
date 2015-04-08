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

package org.keyczar.enums;

/**
 * Encodes different modes of operation:
 *   Cipher Block Chaining (CBC) with initial value (IV)
 *   Counter (CTR) with IV
 *   Electronic Code Book (ECB), no IV
 *   DET-CBC, CBC without IV
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public enum CipherMode {
  CBC("AES/CBC/PKCS5Padding"),
  CTR("AES/CTR/NoPadding"),
  ECB("AES/ECB/NoPadding"),
  DET_CBC("AES/CBC/PKCS5Padding");

  private String jceMode;

  private CipherMode(String s) {
    jceMode = s;
  }

  public String getMode() {
    return jceMode;
  }

  public int getOutputSize(int blockSize, int inputLength) {
    if (this == CBC) {
      return (inputLength / blockSize + 2) * blockSize;
    } else if (this == ECB) {
      return blockSize;
    } else if (this == CTR) {
      return inputLength + blockSize / 2;
    } else if (this == DET_CBC) {
      return (inputLength / blockSize + 1) * blockSize;
    } else {
      return 0;
    }
  }
}
