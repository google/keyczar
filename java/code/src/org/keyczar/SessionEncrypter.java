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

import org.keyczar.annotations.Experimental;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;

/**
 * A session encrypter will generate and encrypt a session key with a given
 * {@link Encrypter}. That session key will be used to encrypt arbitrary data.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
@Experimental
public class SessionEncrypter {
  private final Crypter symmetricCrypter;
  private final byte[] sessionMaterial;

  /**
   * Create a session encrypter. This will generate a session key and encrypt
   * it with the given Encrypter. That session key will be used to encrypt
   * arbitrary data.
   *
   * @param encrypter The encrypter used to encrypt session keys
   * @throws KeyczarException If there is an error instantiating a Crypter 
   */
  public SessionEncrypter(Encrypter encrypter) throws KeyczarException {
    // Using minimum acceptable AES key size, which is 128 bits 
    AesKey aesKey = AesKey.generate(KeyType.AES.getAcceptableSizes().get(0));
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    this.symmetricCrypter = new Crypter(importedKeyReader);
    this.sessionMaterial = encrypter.encrypt(aesKey.getEncoded());
  }

  /**
   * @param plaintext The plaintext to encrypt
   * @return An encryption of the plaintext using the session key
   * @throws KeyczarException
   */
  public byte[] encrypt(byte[] plaintext) throws KeyczarException {
    return symmetricCrypter.encrypt(plaintext);
  }

  /**
   * @return An encryption of a session key
   */
  public byte[] getSessionMaterial() {
    return this.sessionMaterial;
  }
}
