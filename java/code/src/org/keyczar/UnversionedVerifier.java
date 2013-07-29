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

import org.apache.log4j.Logger;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

/**
* Unversioned Verifiers are used strictly to verify standard signatures
* (i.e. HMAC-SHA1, DSA-SHA1, RSA-SHA1) with no key version information.
* Typically, UnversionedVerifiers will read sets of public keys, although may
* also be instantiated with sets of symmetric or private keys.
*
* Since UnversionedVerifiers verify standard signatures, they will try all keys
* in a set until one verifies.
*
* {@link UnversionedSigner} objects should be used with symmetric or private
* key sets to generate unversioned signatures.
*
* @author steveweis@gmail.com (Steve Weis)
*
*/
public class UnversionedVerifier extends Keyczar {
  private static final Logger LOG =
    Logger.getLogger(UnversionedVerifier.class);
  private static final StreamCache<VerifyingStream> VERIFY_CACHE
    = new StreamCache<VerifyingStream>();

  /**
   * Initialize a new UnversionedVerifier with a KeyczarReader.
   * The corresponding key set must have a purpose of either
   * {@link org.keyczar.enums.KeyPurpose#VERIFY} or
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public UnversionedVerifier(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new UnversionedVerifier with a key set location. This will
   * attempt to read the keys using a KeyczarFileReader. The corresponding key
   * set must have a purpose of either
   * {@link org.keyczar.enums.KeyPurpose#VERIFY} or
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public UnversionedVerifier(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  /**
   * Verifies a standard signature on the given byte array of data
   *
   * @param data The data to verify the signature on
   * @param signature The signture to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(byte[] data, byte[] signature) throws KeyczarException {
    return verify(ByteBuffer.wrap(data), ByteBuffer.wrap(signature));
  }

  /**
   * Verifies the standard signature on the data stored in the given ByteBuffer.
   * This method will try all keys until one of them verifies the signature,
   * or else will return false.
   *
   * @param data The data to verify the signature on
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error occurs.
   */
  public boolean verify(ByteBuffer data, ByteBuffer signature)
      throws KeyczarException {
    LOG.debug(Messages.getString("UnversionedVerifier.Verifying", data.remaining()));

    for (KeyczarKey key : versionMap.values()) {
      if (verify(data, signature, key)) {
        return true;
      }
    }
    return false;
  }

  private boolean verify(ByteBuffer data, ByteBuffer signature, KeyczarKey key)
      throws KeyczarException {
    VerifyingStream stream = VERIFY_CACHE.get(key);
    if (stream == null) {
      stream = (VerifyingStream) key.getStream();
    }
    stream.initVerify();
    stream.updateVerify(data.duplicate());
    boolean foundValidSignature = stream.verify(signature.duplicate());
    VERIFY_CACHE.put(key, stream);
    return foundValidSignature;
  }

  /**
   * Verifies the signature on the given String
   *
   * @param data The data to verify the signature on
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(String data, String signature) throws KeyczarException {
    try {
      return verify(data.getBytes(Keyczar.DEFAULT_ENCODING),
          Base64Coder.decodeWebSafe(signature));
    } catch (UnsupportedEncodingException e) {
      throw new KeyczarException(e);
    }
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.VERIFY ||
            purpose == KeyPurpose.SIGN_AND_VERIFY);
  }
}