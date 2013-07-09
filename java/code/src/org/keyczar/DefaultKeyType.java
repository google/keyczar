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

import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.UnsupportedTypeException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyType;
import org.keyczar.keyparams.AesKeyParameters;
import org.keyczar.keyparams.KeyParameters;
import org.keyczar.keyparams.RsaKeyParameters;

import java.util.Arrays;
import java.util.List;

/**
 * Encodes different types of keys each with default key size. Some
 * have multiple acceptable sizes given in a list with the first as default.
 * <ul>
 *   <li>AES:         (128, 192, 256)
 *   <li>HMAC-SHA1:   (256)
 *   <li>DSA Private: (1024)
 *   <li>DSA Public:  (1024)
 *   <li>RSA Private: (4096, 2048, 1024)
 *   <li>RSA Public:  (4096, 2048, 1024)
 *   <li>EC Private:  (256, 384, 521, 192)
 *   <li>EC Public:   (256, 384, 521, 192)
 *   <li>Test:        (1)
 * </ul>
 *
 * <p>JSON Representation currently supports these strings:
 * <ul>
 *   <li>"AES"
 *   <li>"HMAC_SHA1"
 *   <li>"DSA_PRIV"
 *   <li>"DSA_PUB"
 *   <li>"RSA_PRIV"
 *   <li>"RSA_PUB"
 * </ul>
 *
 * Using the default key types is strongly encouraged.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public enum DefaultKeyType implements KeyType {
  AES(Arrays.asList(128, 192, 256)),
  HMAC_SHA1(Arrays.asList(256)),
  DSA_PRIV(Arrays.asList(1024)),
  DSA_PUB(Arrays.asList(1024)),
  RSA_PRIV(Arrays.asList(4096, 2048, 1024)),
  RSA_PUB(Arrays.asList(4096, 2048, 1024)),
  EC_PRIV(Arrays.asList(256, 384, 521, 192)),
  EC_PUB(Arrays.asList(256, 384, 521, 192)),
  TEST(Arrays.asList(1));

  private final List<Integer> acceptableSizes;

  /**
   * Takes a list of acceptable sizes for key lengths. The first one is assumed
   * to be the default size.
   *
   * @param sizes
   */
  private DefaultKeyType(List<Integer> sizes) {
    acceptableSizes = sizes;
  }

  @Override
  public String validateKeyParameters(KeyParameters keyParams) throws KeyczarException {
    validateParametersType(keyParams);
    return validateKeySize(keyParams);
  }

  private void validateParametersType(KeyParameters keyParams)
      throws KeyczarException {
    switch (this) {
      case RSA_PRIV:
        if (!(keyParams instanceof RsaKeyParameters)) {
          throw new KeyczarException("Invalid key parameters type");
        }
        break;
      case AES:
        if (!(keyParams instanceof AesKeyParameters)) {
          throw new KeyczarException("Invalid key parameters type");
        }
        break;
    }
  }

  private String validateKeySize(KeyParameters keyParams)
      throws KeyczarException {
    int keySize = keyParams.getKeySize();
    if (!isAcceptableSize(keySize)) {
      throw new KeyczarException("Invalid key size");
    }
    int defaultKeySize = DefaultKeyType.this.acceptableSizes.get(0);
    if (keySize < defaultKeySize) {
      return Messages.getString("Keyczar.SizeWarning", keySize, defaultKeySize, toString());
    }
    return null;
  }

  /**
   * Returns the default (recommended) key parameters.
   */
  @Override
  public KeyParameters applyDefaultParameters(KeyParameters parameters) {
    switch (DefaultKeyType.this) {
      case RSA_PRIV:
        return new DefaultingRsaKeyParameters(parameters);
      case AES:
        return new DefaultingAesKeyParameters(parameters);
      default:
        return new DefaultingKeyParameters(parameters);
    }
  }

  boolean isAcceptableSize(int size) {
    return acceptableSizes.contains(size);
  }

  @Override
  public String getName() {
    return name();
  }

  @Override
  public Builder getBuilder() {
    return new DefaultKeyBuilder();
  }

  private class DefaultingKeyParameters implements KeyParameters {

    protected final KeyParameters baseParameters;

    public DefaultingKeyParameters(KeyParameters baseParameters) {
      this.baseParameters = baseParameters;
    }

    @Override
    public int getKeySize() throws KeyczarException {
      if (baseParameters == null || baseParameters.getKeySize() == -1) {
        return acceptableSizes.get(0);
      }
      return baseParameters.getKeySize();
    }
  }

  private class DefaultingAesKeyParameters extends DefaultingKeyParameters
      implements AesKeyParameters {

    public DefaultingAesKeyParameters(KeyParameters baseParameters) {
      super(baseParameters);
    }

    @Override
    public HmacKey getHmacKey() throws KeyczarException {
      return HmacKey.generate(HMAC_SHA1.applyDefaultParameters(null));
    }
  }

  private final class DefaultingRsaKeyParameters extends DefaultingKeyParameters
      implements RsaKeyParameters {

    public DefaultingRsaKeyParameters(KeyParameters baseParameters) {
      super(baseParameters);
    }

    @Override
    public RsaPadding getRsaPadding() throws KeyczarException {
      RsaKeyParameters rsaBaseParameters = (RsaKeyParameters) baseParameters;
      if (rsaBaseParameters == null || rsaBaseParameters.getRsaPadding() == null) {
        return RsaPadding.OAEP;
      }
      return rsaBaseParameters.getRsaPadding();
    }
  }

  /**
   * Default key builder that switches on type to use existing reading and
   * generation methods.
   */
  private class DefaultKeyBuilder implements Builder {
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
    public KeyczarKey generate(KeyParameters params) throws KeyczarException {
      params = applyDefaultParameters(params);
      validateKeyParameters(params);

      switch (DefaultKeyType.this) {
        case AES:
          return AesKey.generate((AesKeyParameters) params);
        case HMAC_SHA1:
          return HmacKey.generate(params);
        case DSA_PRIV:
          return DsaPrivateKey.generate(params);
        case RSA_PRIV:
          return RsaPrivateKey.generate((RsaKeyParameters) params);
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
