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
import org.keyczar.exceptions.NoPrimaryKeyException;
import org.keyczar.exceptions.ShortBufferException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;

/**
 * UnversionedSigners may both sign and verify data using sets of symmetric or
 * private keys. Sets of public keys may only be used with {@link Verifier}
 * objects.
 * 
 * UnversionedSigners do not include any key versioning in their outputs. They
 * will return standard signatures (i.e. HMAC-SHA1, RSA-SHA1, DSA-SHA1).
 *
 * {@link UnversionedSigner} objects should be used with symmetric or private key sets to
 * generate signatures.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class UnversionedSigner extends UnversionedVerifier {
  static final int TIMESTAMP_SIZE = 8;
  private static final Logger SIGNER_LOGGER = Logger.getLogger(UnversionedSigner.class);
  private final StreamQueue<SigningStream> SIGN_QUEUE =
    new StreamQueue<SigningStream>();

  /**
   * Initialize a new UnversionedSigner with a KeyczarReader. The corresponding
   * key set must have a purpose
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public UnversionedSigner(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new UnversionedSigner with a key set location. This will
   * attempt to read the keys using a KeyczarFileReader. The corresponding key
   * set must have a purpose of
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public UnversionedSigner(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  /**
   * Returns the size of signatures produced by this UnversionedSigner.
   *
   * @return The size of signatures produced by this UnversionedSigner.
   * @throws KeyczarException If this UnversionedSigner does not have a primary
   *                          or a JCE exception occurs.
   */
  public int digestSize() throws KeyczarException {
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    return ((SigningStream) signingKey.getStream()).digestSize();
  }

  /**
   * Sign the given input and return a signature.
   *
   * @param input The input to sign.
   * @return A byte array representation of a signature.
   * @throws KeyczarException If this UnversionedSigner does not have a primary
   *                          or a JCE exception occurs.
   */
  public byte[] sign(byte[] input) throws KeyczarException {
    ByteBuffer output = ByteBuffer.allocate(digestSize());
    sign(ByteBuffer.wrap(input), output);
    output.reset();
    byte[] outputBytes = new byte[output.remaining()];
    output.get(outputBytes);
    return outputBytes;
  }

  /**
   * This allows other classes in the package to pass in hidden data and/or
   * expiration data to be signed.
   *
   * @param input The input to be signed
   * @param output The destination of this signature
   * @throws KeyczarException
   */
  void sign(ByteBuffer input, ByteBuffer output) throws KeyczarException {
    SIGNER_LOGGER.info(Messages.getString("Signer.Signing", input.remaining()));
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    SigningStream stream = SIGN_QUEUE.poll();
    if (stream == null) {
      stream = (SigningStream) signingKey.getStream();
    }

    int spaceNeeded = digestSize();
    if (output.capacity() < spaceNeeded) {
      throw new ShortBufferException(output.capacity(), spaceNeeded);
    }

    stream.initSign();
    // Sign the header and write it to the output buffer
    output.mark();
    // Sign the input data
    stream.updateSign(input);
    // Write the signature to the output
    stream.sign(output);
    output.limit(output.position());
    SIGN_QUEUE.add(stream);
  }

  /**
   * Signs the given input String and return the output as a web-safe Base64
   * encoded String.
   *
   * @param input The input String to sign.
   * @return A web-safe Base64-encoded representation of a signature on the
   * input.
   * @throws KeyczarException
   */
  public String sign(String input) throws KeyczarException {
    return Base64Coder.encode(sign(input.getBytes()));
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.SIGN_AND_VERIFY;
  }
}