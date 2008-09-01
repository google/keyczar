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

import com.google.gson.annotations.Expose;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Encodes different types of keys each with (default size, output size). Some
 * have multiple acceptable sizes given in a list with the first as default.
 * <ul>
 *   <li>AES:         ((128, 192, 256), 0)
 *   <li>HMAC-SHA1:   (256, 20)
 *   <li>DSA Private: (1024, 48)
 *   <li>DSA Public:  (1024, 48)
 *   <li>RSA Private: ((2048, 1024, 768, 512), 256)
 *   <li>RSA Public:  ((2048, 1024, 768, 512), 256)
 *   <li>EC Private:  ((256, 384, 521, 192), 70)
 *   <li>EC Public:   ((256, 384, 521, 192), 70)
 *   <li>Test:        (1, 0)
 * </ul>
 *
 * <p>JSON Representation currently supports these strings:
 * <ul>
 *   <li>"AES"
 *   <li>"HMAC_SHA1"
 *   <li>"DSA_PRIV"
 *   <li>"DSA_PUB"
 * </ul>
 *
 *  @author steveweis@gmail.com (Steve Weis)
 *  @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public enum KeyType {
  AES("AES", 0, Arrays.asList(128, 192, 256), 0),
  HMAC_SHA1("HMAC-SHA1",1, Arrays.asList(256), 20),
  DSA_PRIV("DSA Private", 2, Arrays.asList(1024), 48),
  DSA_PUB("DSA Public", 3, Arrays.asList(1024), 48),
  RSA_PRIV("RSA Private", 4, Arrays.asList(2048, 1024, 768, 512), 256),
  RSA_PUB("RSA Public", 5, Arrays.asList(2048, 1024, 768, 512), 256),
  EC_PRIV("EC Private", 6, Arrays.asList(256, 384, 521, 192), 70),
  EC_PUB("EC Public", 7, Arrays.asList(256, 384, 521, 192), 70),
  TEST("Test", 127, Arrays.asList(1), 0);

  private int outputSize;
  private List<Integer> acceptableSizes;
  private String name;
  @Expose private int value;

  /**
   * Takes a list of acceptable sizes for key lengths. The first one is assumed
   * to be the default size.
   *
   * @param v
   * @param sizes
   * @param outputSize
   */
  private KeyType(String n, int v, List<Integer> sizes, int outputSize) {
    name = n;
    value = v;
    this.acceptableSizes = sizes;
    this.outputSize = outputSize;
  }

  /**
   * Returns the default (recommended) key size.
   *
   * @return default key size in bits
   */
  public int defaultSize() {
    return acceptableSizes.get(0);
  }

  public int getOutputSize() {
    return outputSize;
  }

  /**
   * Checks whether a given key size is acceptable.
   *
   * @param size integer key size
   * @return True if size is acceptable, False otherwise.
   */
  public boolean isAcceptableSize(int size) {
    return acceptableSizes.contains(size);
  }

  public List<Integer> getAcceptableSizes() {
    return Collections.unmodifiableList(acceptableSizes);
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
        return RSA_PRIV;
      case 5:
        return RSA_PUB;
      case 6:
    	return EC_PRIV;
      case 7:
        return EC_PUB;
      case 127:
        return TEST;
    }
    return null;
  }

  @Override
  public String toString() {
    return name;
  }
}