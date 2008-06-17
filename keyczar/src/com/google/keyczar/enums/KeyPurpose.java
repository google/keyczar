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

/**
 * Encodes different possible uses of a key:
 * <ul> 
 *   <li>Decrypt and Encrypt,
 *   <li>Encrypt Only,
 *   <li>Sign and Verify,
 *   <li>Verify Only, and
 *   <li>Test.
 * </ul>
 * 
 * <p>JSON Representation currently supports these strings:
 * <ul>
 *   <li>"DECRYPT_AND_ENCRYPT"
 *   <li>"ENCRYPT"
 *   <li>"SIGN_AND_VERIFY"
 *   <li>"VERIFY"
 * </ul>
 *   
 *  @author steveweis@gmail.com (Steve Weis)
 *  
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
      case 127: // TODO: Changed from 255 to 127 to match constructor call. OK?
        return TEST;
    }
    return null;
  }
}
