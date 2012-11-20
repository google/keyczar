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

package org.keyczar;

import org.keyczar.annotations.Experimental;
import org.keyczar.exceptions.Base64DecodingException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Base64Coder;

/**
 * Perform a signed session based decryption.
 * 
 * The flow is as follows:
 * 
 * 1) decrypt the session material
 * 2) get the AES key
 * 3) detach the signature for verification. 
 * 4) verify the DSA signature with nonce
 * 5) decrypt the ciphertext with session AES key.
 * 
 * @author normandl@google.com (David Norman)
 *
 */
@Experimental
public class SignedSessionDecrypter {
  private final SessionMaterial session;
  private final Verifier verifier;
  
  public SignedSessionDecrypter(Crypter crypter, Verifier verifier,
      String session) throws Base64DecodingException, KeyczarException {
    this.verifier= verifier;
    
    // decode & decrypt session
    byte[] decoded = Base64Coder.decodeWebSafe(session);
    String sessionString = new String(crypter.decrypt(decoded));
    this.session = SessionMaterial.read(sessionString);
  }
  
  /**
   * Verify and decypt the signed blob.
   * 
   * @param signedBlob byte[] to decrypt
   * @return unencrypted/unencoded payload.
   * @throws KeyczarException
   */
  public byte[] decrypt(final byte[] signedBlob) throws KeyczarException {
    if (null == session) {
      throw new KeyczarException("Session has not been initialized");
    }
    
    AesKey aesKey = session.getKey();
    ImportedKeyReader importedKeyReader = new ImportedKeyReader(aesKey);
    Crypter symmetricCrypter = new Crypter(importedKeyReader);

    byte[] ciphertext =
      verifier.getAttachedData(signedBlob, Base64Coder.decodeWebSafe(session.getNonce()));
        
    return symmetricCrypter.decrypt(ciphertext);
  }
}
