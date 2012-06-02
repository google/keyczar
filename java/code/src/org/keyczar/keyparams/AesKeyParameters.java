// Copyright 2012 Google Inc. All Rights Reserved.

package org.keyczar.keyparams;

import org.keyczar.HmacKey;
import org.keyczar.exceptions.KeyczarException;

/**
 * Interface for objects which provide configuration information for RSA key generation.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public interface AesKeyParameters extends KeyParameters {

  /**
   * Returns HMAC key which should be used with the AES key to verify ciphertexts.
   * @throws KeyczarException
   */
  HmacKey getHmacKey() throws KeyczarException;
}
