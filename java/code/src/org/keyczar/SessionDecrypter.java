/*
 * Copyright 2010 Google Inc.
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

import org.keyczar.exceptions.KeyczarException;

/**
 * A SessionDecrypter will be instantiated with session material containing an
 * encrypted symmetric key. That key will be decrypted with the given
 * {@link Crypter} and used to instantiate another {@link Crypter}.
 *
 * This class and {@link SessionEncrypter} have been deprecated in favor of
 * {@link SessionCrypter}.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
@Deprecated
public class SessionDecrypter {
  private final Crypter symmetricCrypter;

  /**
   * @param crypter The crypter to decrypt session material with
   * @param sessionMaterial An encrypted symmetric key to decrypt
   * @throws KeyczarException If there is an error during decryption
   */
  public SessionDecrypter(Crypter crypter, byte[] sessionMaterial)
      throws KeyczarException {
    byte[] packedKeys = crypter.decrypt(sessionMaterial);
    AesKey aesKey = AesKey.fromPackedKey(packedKeys);
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    this.symmetricCrypter = new Crypter(importedKeyReader);
  }

  /**
   * @param ciphertext Session ciphertext to encrypt
   * @return The decrypted plaintext
   * @throws KeyczarException If there is an error during decryption
   */
  public byte[] decrypt(byte[] ciphertext) throws KeyczarException {
    return symmetricCrypter.decrypt(ciphertext);
  }
}
