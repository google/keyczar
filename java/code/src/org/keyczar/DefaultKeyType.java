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

package org.keyczar;

import org.keyczar.AesKey;
import org.keyczar.DsaPrivateKey;
import org.keyczar.DsaPublicKey;
import org.keyczar.HmacKey;
import org.keyczar.RsaPrivateKey;
import org.keyczar.RsaPublicKey;

import org.keyczar.enums.RsaPadding;

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.UnsupportedTypeException;

import org.keyczar.i18n.Messages;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keyczar.KeyczarKey;
import org.keyczar.interfaces.KeyType;

/**
 * Encodes different types of keys each with (default size, output size). Some
 * have multiple acceptable sizes given in a list with the first as default.
 * <ul>
 *   <li>AES:         ((128, 192, 256), 0)
 *   <li>HMAC-SHA1:   (256, 20)
 *   <li>DSA Private: (1024, 48)
 *   <li>DSA Public:  (1024, 48)
 *   <li>RSA Private: ((4096, 2048, 1024), 256)
 *   <li>RSA Public:  ((4096, 2048, 1024), 256)
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
 * Using the default key types is strongly encouraged.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public enum DefaultKeyType implements KeyType {
  AES(Arrays.asList(128, 192, 256), 0),
  HMAC_SHA1(Arrays.asList(256), 20),
  DSA_PRIV(Arrays.asList(1024), 48),
  DSA_PUB(Arrays.asList(1024), 48),
  RSA_PRIV(Arrays.asList(4096, 2048, 1024), Arrays.asList(512, 256, 128)),
  RSA_PUB(Arrays.asList(4096, 2048, 1024), Arrays.asList(512, 256, 128)),
  // TODO(sweis): The ECC output size is not correct. Fix this.
  EC_PRIV(Arrays.asList(256, 384, 521, 192), 70),
  EC_PUB(Arrays.asList(256, 384, 521, 192), 70),
  TEST(Arrays.asList(1), 0);

  private static Map<String, KeyType> typeMapping;
  private final Map<Integer, Integer> outputSizeMap = new HashMap<Integer, Integer>();
  private final List<Integer> acceptableSizes;

  /**
   * Takes a list of acceptable sizes for key lengths. The first one is assumed
   * to be the default size.
   *
   * @param sizes
   * @param outputSize
   */
  private DefaultKeyType(List<Integer> sizes, int outputSize) {
    this.acceptableSizes = sizes;
    for (int size : acceptableSizes) {
        // All keys have the same default output size
        outputSizeMap.put(size, outputSize);
    }
    addToMapping(this.name(), this);
  }

  /**
   * Takes a list of acceptable sizes for key lengths. The first one is assumed
   * to be the default size.
   *
   * @param sizes
   * @param outputSizeList
   */
  private DefaultKeyType(List<Integer> sizes, List<Integer> outputSizeList) {
    this.acceptableSizes = sizes;
    for (int i = 0; i < sizes.size(); i++) {
        outputSizeMap.put(acceptableSizes.get(i), outputSizeList.get(i));
    }
    addToMapping(this.name(), this);
  }

  private static void addToMapping(String s, KeyType type) {
    if (typeMapping == null) {
      typeMapping = new HashMap<String, KeyType>();
    }
    typeMapping.put(s, type);
  }

  public static KeyType getTypeByName(String s) {
    return typeMapping.get(s);
  }

  /**
   * Returns the default (recommended) key size.
   *
   * @return default key size in bits
   */
  @Override
  public int defaultSize() {
    return acceptableSizes.get(0);
  }

  @Override
  public int getOutputSize(int keySize) {
    return outputSizeMap.get(keySize);
  }

  @Override
  public int getOutputSize() {
    return getOutputSize(defaultSize());
  }

  /**
   * Checks whether a given key size is acceptable.
   *
   * @param size integer key size
   * @return True if size is acceptable, False otherwise.
   */
  @Override
  public boolean isAcceptableSize(int size) {
    return acceptableSizes.contains(size);
  }

  @Override
  public List<Integer> getAcceptableSizes() {
    return Collections.unmodifiableList(acceptableSizes);
  }

  @Override
  public String getName() {
    return this.name();
  }

  @Override
  public Builder getBuilder() {
    return new DefaultKeyBuilder();
  }

  Builder getRsaBuilder(RsaPadding padding) throws KeyczarException {
    if (DefaultKeyType.this != RSA_PRIV) {
      throw new KeyczarException(Messages.getString(
          "InvalidKeyType", DefaultKeyType.this));
    }
    return new DefaultKeyBuilder(padding);
  }

  /**
   * Default key builder that switches on type to use existing reading and
   * generation methods.
   */
  private class DefaultKeyBuilder implements Builder {
    private final RsaPadding padding;

    /**
     * TODO(jmscheiner): temporarily hacked in to support RsaPadding.
     */
    private DefaultKeyBuilder(RsaPadding padding) {
      this.padding = padding;
    }

    private DefaultKeyBuilder() {
      this.padding = null;
    }

    @Override
    public KeyczarKey read(String key) throws KeyczarException {
      switch (DefaultKeyType.this) {
        case AES:
          return AesKey.read(key);
        case HMAC_SHA1:
          return HmacKey.read(key);
        case DSA_PRIV:
          return DsaPrivateKey.read(key);
        case DSA_PUB:
          return DsaPublicKey.read(key);
        case RSA_PRIV:
          return RsaPrivateKey.read(key);
        case RSA_PUB:
          return RsaPublicKey.read(key);
        // Currently unsupported. See "unofficial" directory.
        //case EC_PRIV:
        //    return EcPrivateKey.read(key);
        //case EC_PUB:
        //    return EcPublicKey.read(key);
      }
      throw new UnsupportedTypeException(DefaultKeyType.this);
    }

    @Override
    public KeyczarKey generate(int keySize) throws KeyczarException {
      switch (DefaultKeyType.this) {
        case AES:
          return AesKey.generate(keySize);
        case HMAC_SHA1:
          return HmacKey.generate(keySize);
        case DSA_PRIV:
          return DsaPrivateKey.generate(keySize);
        case RSA_PRIV:
          return RsaPrivateKey.generate(keySize, padding);
        // Currently unsupported. See "unofficial" directory.
        //case EC_PRIV:
        //    return EcPrivateKey.generate(keySize);
        case RSA_PUB: case DSA_PUB:
          throw new KeyczarException(Messages.getString(
              "KeyczarKey.PublicKeyExport", DefaultKeyType.this));
      }
      throw new UnsupportedTypeException(DefaultKeyType.this);
    }
  }
}
