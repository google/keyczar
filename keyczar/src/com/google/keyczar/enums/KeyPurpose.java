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

// TODO: Finish JavaDocs
/**
 * Encodes different possible uses of a key: 
 *   Decrypt and Encrypt
 *   Encrypt Only
 *   Sign and Verify
 *   Verify Only
 *   Test
 */

public enum KeyPurpose {
  DECRYPT_AND_ENCRYPT(0), ENCRYPT(1), SIGN_AND_VERIFY(2), TEST(127), VERIFY(3);

  private int value;

  private KeyPurpose(int v) {
    value = v;
  }

  int getValue() {
    return value;
  }

  static KeyPurpose getPurpose(int value) {
    switch (value) {
    case 0:
      return DECRYPT_AND_ENCRYPT;
    case 1:
      return ENCRYPT;
    case 2:
      return SIGN_AND_VERIFY;
    case 3:
      return VERIFY;
    case 255: // TODO: Fix -- should this be 127? to match constructor call?
      return TEST;
    }
    return null;
  }
}
