/*
 * Copyright 2011 Google Inc.
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

import java.security.interfaces.RSAPublicKey;

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Util;

/**
 * Enumeration of available options for padding of plaintexts encrypted with
 * RSA.
 *
 * Previously, only OAEP padding was supported.  Some users had a hard need
 * for PKCS#1 v1.5 padding support, so it was added.  However, OAEP is the
 * preferred option because with PKCS#1 v1.5 RSA vulnerable to some chosen
 * ciphertext attacks.
 *
 * The default is OAEP.  For maximum compatibility with other Keyczar
 * implementations, the padding field is omitted when writing keys with OAEP
 * padding; it is only present when it is set to the value "PKCS".
 *
 * @author swillden@google.com (Shawn Willden)
 */
public enum RsaPadding {
  OAEP("RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING"),
  PKCS("RSA/ECB/PKCS1PADDING");

  private final String cryptAlgorithm;

  private RsaPadding(String cryptAlgorithm) {
    this.cryptAlgorithm = cryptAlgorithm;
  }

  public String getCryptAlgorithm() {
    return cryptAlgorithm;
  }

  public byte[] computeFullHash(RSAPublicKey key) throws KeyczarException {
    switch (this) {
      case OAEP:
        return Util.prefixHash(
            Util.stripLeadingZeros(key.getModulus().toByteArray()),
            Util.stripLeadingZeros(key.getPublicExponent().toByteArray()));
      case PKCS:
        return Util.prefixHash(
            key.getModulus().toByteArray(),
            key.getPublicExponent().toByteArray());
      default:
        throw new KeyczarException("Bug! Unknown padding type");
    }
  }
}