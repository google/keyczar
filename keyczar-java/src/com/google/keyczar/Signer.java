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

package com.google.keyczar;

import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.exceptions.NoPrimaryKeyException;
import com.google.keyczar.exceptions.ShortBufferException;
import com.google.keyczar.interfaces.KeyczarReader;
import com.google.keyczar.interfaces.SigningStream;
import com.google.keyczar.util.Base64Coder;

import java.nio.ByteBuffer;


/**
 * Signers may both encrypt and decrypt data using sets of symmetric or private
 * keys. Sets of public keys may only be used with {@link Verifier} objects.
 * 
 * {@link Signer} objects should be used with symmetric or private key sets to
 * generate signatures.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class Signer extends Verifier {
  private final StreamQueue<SigningStream> SIGN_QUEUE =
    new StreamQueue<SigningStream>();

  /**
   * Initialize a new Signer with a KeyczarReader. The corresponding key set
   * must have a purpose {@link com.google.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
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
   * must have a purpose of {@link com.google.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
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
    return HEADER_SIZE + ((SigningStream) signingKey.getStream()).digestSize();
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
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    SigningStream stream = SIGN_QUEUE.poll();
    if (stream == null) {
      stream = (SigningStream) signingKey.getStream();
    }

    if (output.capacity() < digestSize()) {
      throw new ShortBufferException(output.capacity(), digestSize());
    }
    ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
    signingKey.copyHeader(header);
    header.rewind();
    stream.initSign();

    // Sign the header and write it to the output buffer
    output.mark();
    output.put(header);
    header.rewind();
    stream.updateSign(header);

    // Write the signature to the output
    stream.updateSign(input);
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
    return (purpose == KeyPurpose.SIGN_AND_VERIFY);
  }
}
