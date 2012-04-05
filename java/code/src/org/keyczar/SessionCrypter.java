/*
 * Copyright 2012 Google Inc.
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

import org.keyczar.annotations.Experimental;
import org.keyczar.exceptions.KeyczarException;

/**
 * A session crypter will generate and encrypt a session key with a given
 * {@link Encrypter}. That session key will be used to encrypt and decrypt
 * arbitrary data.
 *
 * @author jmscheiner@google.com (Justin Scheiner)
 */
@Experimental
public class SessionCrypter extends SessionEncrypter {
  /**
   * Create a session crypter. This will generate a session key and encrypt
   * it with the given Encrypter. That session key will be used to encrypt
   * and decrypt arbitrary data.
   *
   * @param encrypter The encrypter used to encrypt session keys
   * @throws KeyczarException If there is an error instantiating a Crypter
   */
  public SessionCrypter(Encrypter encrypter) throws KeyczarException {
    super(encrypter);
  }

  /**
   * @param ciphertext The cipher text to decrypt
   * @return The decrypted plain text
   * @throws KeyczarException If there is an error during decryption
   */
  public byte[] decrypt(byte[] ciphertext) throws KeyczarException {
    return getSymmetricCrypter().decrypt(ciphertext);
  }
}
