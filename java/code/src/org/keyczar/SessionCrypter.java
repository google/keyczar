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
import org.keyczar.keyparams.AesKeyParameters;

/**
 * A {@link SessionCrypter} encrypts and decrypts session key encrypted data.
 * The session key is encrypted and made available as session material so that
 * remote {@link SessionCrypter}s can be created.
 *
 * A typical exchange may look like,
 *
 * <pre>
 * SessionCrypter crypter = new SessionCrypter(keyEncrypter);
 * byte[] encryptedData = crypter.encrypt(data);
 * byte[] sessionMaterial = crypter.getSessionMaterial();
 * </pre>
 *
 *    ... and on the remote side ...
 *
 * <pre>
 * SessionCrypter crypter = new SessionCrypter(keyCrypter, sessionMaterial);
 * byte[] decryptedData = crypter.decrypt(data);
 * </pre>
 *
 * where the expectation is that keyEncrypter and keyCrypter are compatible.
 *
 * @author jmscheiner@google.com (Justin Scheiner)
 * @author steveweis@gmail.com (Steve Weis)
 */
@Experimental
public class SessionCrypter {
  private final Crypter symmetricCrypter;
  private final byte[] sessionMaterial;

  /**
   * Create a session crypter. This will generate a session key and encrypt
   * it with the given Encrypter. That session key will be used to encrypt
   * and decrypt arbitrary data.
   *
   * @param encrypter The encrypter used to encrypt session keys
   * @throws KeyczarException If there is an error instantiating a Crypter
   */
  public SessionCrypter(Encrypter encrypter) throws KeyczarException {
    AesKey aesKey =
        AesKey.generate((AesKeyParameters) DefaultKeyType.AES.applyDefaultParameters(null));
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    this.symmetricCrypter = new Crypter(importedKeyReader);
    this.sessionMaterial = encrypter.encrypt(aesKey.getEncoded());
  }

  /**
   * Create a session crypter. This will use the crypter to decrypt the given
   * session material and use it to create a session key. That session key will
   * be used to encrypt and decrypt arbitrary data.
   *
   * @param crypter The crypter to decrypt session material with
   * @param sessionMaterial An encrypted symmetric key to decrypt
   * @throws KeyczarException If there is an error during decryption
   */
  public SessionCrypter(Crypter crypter, byte[] sessionMaterial)
      throws KeyczarException {
    byte[] packedKeys = crypter.decrypt(sessionMaterial);
    AesKey aesKey = AesKey.fromPackedKey(packedKeys);
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    this.symmetricCrypter = new Crypter(importedKeyReader);
    this.sessionMaterial = sessionMaterial;
  }

  /**
   * @param ciphertext The cipher text to decrypt
   * @return The decrypted plain text
   * @throws KeyczarException If there is an error during decryption
   */
  public byte[] decrypt(byte[] ciphertext) throws KeyczarException {
    return symmetricCrypter.decrypt(ciphertext);
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
   * Returns an encrypted session key useful for initializing remote
   * {@link SessionCrypter}'s.
   *
   * @return the encrypted session key
   */
  public byte[] getSessionMaterial() {
    return this.sessionMaterial;
  }
}
