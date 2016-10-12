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

import org.keyczar.enums.KeyPurpose;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.NoPrimaryKeyException;
import org.keyczar.exceptions.ShortBufferException;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Signers may both sign and verify data using sets of symmetric or private
 * keys. Sets of public keys may only be used with {@link Verifier} objects.
 *
 * {@link Signer} objects should be used with symmetric or private key sets to
 * generate signatures.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Signer extends Verifier {
  static final int TIMESTAMP_SIZE = 8;

  /**
   * Initialize a new Signer with a KeyczarReader. The corresponding key set
   * must have a purpose {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Signer(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new Signer with a key set location. This will attempt to
   * read the keys using a KeyczarFileReader. The corresponding key set
   * must have a purpose of {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Signer(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  /**
   * Returns the size of signatures produced by this Signer.
   *
   * @return The size of signatures produced by this Signer.
   * @throws KeyczarException If this Signer does not have a primary or a
   * JCE exception occurs.
   */
  public int digestSize() throws KeyczarException {
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    SigningStream stream = (SigningStream) signingKey.getStream();
    int result = HEADER_SIZE + stream.digestSize();
    signingKey.addStreamToCacheForReuse(stream);
    return result;
  }

  /**
   * Sign the given input and return a signature.
   *
   * @param input The input to sign.
   * @return A byte array representation of a signature.
   * @throws KeyczarException If this Signer does not have a primary or a
   * JCE exception occurs.
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
   * Sign the given input and write the signature to the given ByteBuffer
   *
   * @param input The input to sign.
   * @param output The ByteBuffer to write the signature in.
   * @throws KeyczarException If this Signer does not have a primary or a
   * JCE exception occurs.
   */
  public void sign(ByteBuffer input, ByteBuffer output) throws KeyczarException {
    sign(input, null, 0, output);
  }

  /**g
   * This allows other classes in the package to pass in hidden data and/or
   * expiration data to be signed.
   *
   * @param input The input to be signed
   * @param hidden Hidden data to be signed
   * @param expirationTime The expiration time of this signature
   * @param output The destination of this signature
   *
   * @throws KeyczarException
   */
  void sign(ByteBuffer input, ByteBuffer hidden, long expirationTime, ByteBuffer output)
      throws KeyczarException {
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    SigningStream stream = (SigningStream) signingKey.getStream();

    int spaceNeeded = digestSize();
    if (expirationTime > 0) {
      spaceNeeded += TIMESTAMP_SIZE;
    }
    if (output.capacity() < spaceNeeded) {
      throw new ShortBufferException(output.capacity(), spaceNeeded);
    }

    ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
    signingKey.copyHeader(header);
    header.rewind();
    stream.initSign();

    // Sign the header and write it to the output buffer
    output.mark();
    output.put(header);

    if (expirationTime > 0) {
      // Write an expiration time following the header and sign it.
      ByteBuffer expiration = ByteBuffer.wrap(Util.fromLong(expirationTime));
      output.put(expiration);
      expiration.rewind();
      stream.updateSign(expiration);
    }

    if (hidden != null && hidden.remaining() > 0) {
      // Sign any hidden data
      stream.updateSign(hidden);
    }

    // Sign the input data
    stream.updateSign(input);
    // Sign the version byte
    stream.updateSign(ByteBuffer.wrap(FORMAT_BYTES));

    // Write the signature to the output
    stream.sign(output);
    output.limit(output.position());
    
    signingKey.addStreamToCacheForReuse(stream);

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
    try {
      return Base64Coder.encodeWebSafe(sign(input.getBytes(DEFAULT_ENCODING)));
    } catch (UnsupportedEncodingException e) {
      throw new KeyczarException(e);
    }
  }

  /**
   * Signs an input blob and returns the data with attached signature
   *
   * @param blob Data to sign
   * @param hidden Hidden data or nonce to include in signature
   * @return The input data with an attached signature
   */
  public byte[] attachedSign(final byte[] blob, final byte[] hidden) throws KeyczarException {
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }

    SigningStream stream = (SigningStream) signingKey.getStream();

    stream.initSign();
    // Attached signature signs:
    // [blob | hidden.length | hidden | format] or [blob | 0 | format]
    byte[] hiddenPlusLength = Util.fromInt(0);
    if (hidden.length > 0) {
      hiddenPlusLength = Util.lenPrefix(hidden);
    }

    stream.updateSign(ByteBuffer.wrap(blob));
    stream.updateSign(ByteBuffer.wrap(hiddenPlusLength));
    stream.updateSign(ByteBuffer.wrap(FORMAT_BYTES));

    // now get signature output
    ByteBuffer output = ByteBuffer.allocate(stream.digestSize());
    output.mark();

    stream.sign(output);
    output.limit(output.position());

    // Attached signature format is:
    // [Format number | 4 bytes of key hash | blob size | blob | raw signature]
    byte[] signature =
        Util.cat(FORMAT_BYTES, signingKey.hash(), Util.lenPrefix(blob),
            Arrays.copyOfRange(output.array(), 0, output.position()));
    signingKey.addStreamToCacheForReuse(stream);
    return signature;
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.SIGN_AND_VERIFY;
  }
}
