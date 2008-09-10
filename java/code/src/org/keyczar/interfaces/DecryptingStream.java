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
 * Decrypting streams are able to decrypt and verify data which has been
 * encrypted by {@link EncryptingStream} objects.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public interface DecryptingStream extends Stream {

  /**
   * Returns a Verifying Stream able to verify signatures on ciphertext inputs
   * to this Decrypting Stream
   *
   * @return A Verifying Stream associated with this stream
   */
  VerifyingStream getVerifyingStream();

  /**
   * Initializes this stream for decryption. May consume some bytes of the
   * input; typically to read an IV if any exists. This must be called before
   * updateDecrypt() or doFinalDecrypt().
   *
   * @param input The input containing any IV or other header data.
   * @throws KeyczarException If there is any error initializing this Stream;
   *                          typically this would be a Java JCE exception.
   */
  void initDecrypt(ByteBuffer input) throws KeyczarException;

  /**
   * Update with more input to decrypt. Write any decrypted output to the given
   * output buffer. Some decrypted output may be buffered and not written out
   * until the next call to updateDecrypt() or doFinalDecrypt().
   *
   * @param input The input to decrypt.
   * @param output The decrypted output, if any.
   * @return The number of bytes written to the output.
   * @throws KeyczarException If a Java JCE error occurs or the output buffer
   *                          is too small.
   */
  int updateDecrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;

  /**
   * Do the final decrypt operation. Reads any remaining bytes from the input,
   * decrypts them, and writes the plaintext to the output.
   *
   * @param input The input to decrypt.
   * @param output The decrypted output, if any.
   * @return The number of bytes written to the output.
   * @throws KeyczarException If a Java JCE error occurs or the output buffer
   *                          is too small.
   */
  int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;

  /**
   * Returns the maximum length of the output given the input length.
   *
   * @param inputLen The input length
   * @return The max lenght of the output given the input length
   */
  int maxOutputSize(int inputLen);
}