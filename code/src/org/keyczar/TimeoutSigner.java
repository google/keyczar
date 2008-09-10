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

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Base64Coder;

import java.nio.ByteBuffer;

/**
 * Timeout signers can generate signatures that are valid until a specified
 * expiration time. Timeout signatures are verified by
 * {@link org.keyczar.TimeoutVerifier} objects.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class TimeoutSigner extends TimeoutVerifier {
  private Signer signer;

  /**
   * Initialize a new TimeoutSigner with a KeyczarReader.
   * The corresponding key set must have a purpose
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public TimeoutSigner(KeyczarReader reader) throws KeyczarException {
    this.signer = new Signer(reader);
    setVerifier(this.signer);
  }

  /**
   * Initialize a new TimeoutSigner with a key set location. This will
   * attempt to read the keys using a KeyczarFileReader. The corresponding
   * key set must have a purpose of
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public TimeoutSigner(String fileLocation) throws KeyczarException {
    this.signer = new Signer(fileLocation);
    setVerifier(this.signer);
  }

  /**
   * Initialize a new TimeoutSigner with a Signer object.
   *
   * @param signer Signer to be used for timeout signatures
   */
  public TimeoutSigner(Signer signer){
    this.signer = signer;
    setVerifier(this.signer);
  }

  /**
   * Sign the given input and return a signature that is valid until the
   * expiration time given as the number of milliseconds since "the epoch"
   * of 1/1/1970 00:00:00 GMT
   *
   * @param input The input to be signed
   * @param expirationTime The expiration time in milliseconds since 1/1/1970
   * 00:00:00 GMT
   * @return The signature as a web safe Base64 string
   * @throws KeyczarException
   */
  public String timeoutSign(String input, long expirationTime)
      throws KeyczarException {
    return Base64Coder.encode(timeoutSign(input.getBytes(), expirationTime));
  }

  /**
   * Sign the given input and return a signature that is valid until the
   * expiration time given as the number of milliseconds since "the epoch"
   * of 1/1/1970 00:00:00 GMT
   *
   * @param input The input to be signed
   * @param expirationTime The expiration time in milliseconds since 1/1/1970
   * 00:00:00 GMT
   * @return The signature
   * @throws KeyczarException
   */
  public byte[] timeoutSign(byte[] input, long expirationTime)
      throws KeyczarException {
    ByteBuffer output =
      ByteBuffer.allocate(signer.digestSize() + Signer.TIMESTAMP_SIZE);
    timeoutSign(ByteBuffer.wrap(input), expirationTime, output);
    output.reset();
    byte[] outputBytes = new byte[output.remaining()];
    output.get(outputBytes);
    return outputBytes;
  }

  /**
   * Signs the input and produces a signature that is valid until the
   * expiration time given as the number of milliseconds since "the epoch"
   * of 1/1/1970 00:00:00 GMT
   *
   * @param input The input to be signed
   * @param expirationTime The expiration time in milliseconds since 1/1/1970
   * 00:00:00 GMT
   * @param output The destination of this signature
   * @throws KeyczarException
   */
  public void timeoutSign(ByteBuffer input, long expirationTime,
      ByteBuffer output) throws KeyczarException {
    signer.sign(input, null, expirationTime, output);
  }
}