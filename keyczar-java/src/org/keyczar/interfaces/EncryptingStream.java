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

package org.keyczar.interfaces;

import org.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;

/**
 * Encrypting streams are able to encrypt and sign data.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public interface EncryptingStream extends Stream {

  /**
   * Returns a Signing Stream able to sign ciphertexts produced by this
   * EncryptingStream.
   *
   * @return A Signg Stream associated with this stream
   */
  SigningStream getSigningStream() throws KeyczarException;

  /**
   * Initializes this stream for encryption. May write some header material to
   * the output, for example an IV. This must be called before
   * updateEncrypt() or doFinalEncrypt().
   *
   * @param output The output where any IV material will be written.
   * @return The number of bytes written to the output.
   * @throws KeyczarException If there is any error initializing this Stream;
   *                          typically this would be a Java JCE exception.
   */
  int initEncrypt(ByteBuffer output) throws KeyczarException;

  /**
   * Update with more input to encrypt. Write any encrypted output to the given
   * output buffer. Some encrypted output may be buffered and not written out
   * until the next call to updateEncrypt() or doFinalEncrypt().
   *
   * @param input The input to encrypt.
   * @param output The encrypted output, if any.
   * @return The number of bytes written to the output.
   * @throws KeyczarException If a Java JCE error occurs or the output buffer
   *                          is too small.
   */
  int updateEncrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;

  /**
   * Do the final encrypt operation. Reads any remaining bytes from the input,
   * encrypts them, and writes the ciphertext to the output.
   *
   * @param input The input to encrypt.
   * @param output The encrypted output, if any.
   * @return The number of bytes written to the output.
   * @throws KeyczarException If a Java JCE error occurs or the output buffer
   *                          is too small.
   */
  int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;

  /**
   * Given the length of an input, return the maximum possible length of
   * the output (including headers, the actual ciphertext, and the signature).
   *
   * @param inputLen
   * @return maximum length of output
   */
  int maxOutputSize(int inputLen);
}