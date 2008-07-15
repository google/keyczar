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
import org.keyczar.exceptions.BadVersionException;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortSignatureException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;

import java.nio.ByteBuffer;


/**
* Verifiers are used strictly to verify signatures. Typically, Verifiers will
* read sets of public keys, although may also be instantiated with sets of
* symmetric or private keys.
* 
* {@link Signer} objects should be used with symmetric or private key sets to
* generate signatures.
* 
* @author steveweis@gmail.com (Steve Weis)
*/
public class Verifier extends Keyczar {
  private static final Logger logger = Logger.getLogger(Verifier.class);
  private static final StreamCache<VerifyingStream> VERIFY_CACHE
    = new StreamCache<VerifyingStream>();

  /**
   * Initialize a new Verifier with a KeyczarReader. The corresponding key set
   * must have a purpose of either {@link org.keyczar.enums.KeyPurpose#VERIFY} or
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   * 
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Verifier(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new Verifier with a key set location. This will attempt to
   * read the keys using a KeyczarFileReader. The corresponding key set
   * must have a purpose of either 
   * {@link org.keyczar.enums.KeyPurpose#VERIFY} or
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}
   *  
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Verifier(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  /**
   * Verifies a signature on the given byte array of data
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
   * Verifies the signature on the data stored in the given ByteBuffer
   * 
   * @param data The data to verify the signature on
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(ByteBuffer data, ByteBuffer signature)
      throws KeyczarException {
    logger.info(Messages.getString("Verifier.Verifying", data.remaining()));
    if (signature.remaining() < HEADER_SIZE) {
      throw new ShortSignatureException(signature.remaining());
    }

    byte version = signature.get();
    if (version != VERSION) {
      throw new BadVersionException(version);
    }

    byte[] hash = new byte[KEY_HASH_SIZE];
    signature.get(hash);
    KeyczarKey key = getKey(hash);

    if (key == null) {
      throw new KeyNotFoundException(hash);
    }

    // Copy the header from the key.
    ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
    key.copyHeader(header);
    header.rewind();

    VerifyingStream stream = VERIFY_CACHE.get(key);
    if (stream == null) {
      stream = (VerifyingStream) key.getStream();
    }
    stream.initVerify();
    stream.updateVerify(header);
    stream.updateVerify(data);
    boolean result = stream.verify(signature);
    VERIFY_CACHE.put(key, stream);
    return result;
  }

  /**
   * Verifies the signature on the data stored in the given ByteBuffer
   * 
   * @param data The data to verify the signature on
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(String data, String signature) throws KeyczarException {
    return verify(data.getBytes(), Base64Coder.decode(signature));
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.VERIFY || 
            purpose == KeyPurpose.SIGN_AND_VERIFY);
  }
}