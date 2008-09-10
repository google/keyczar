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
 * Signing streams are able to sign data
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public interface SigningStream extends Stream {

  /**
   * Initializes this stream for signing.
   *
   * @throws KeyczarException If any Java JCE errors occur
   */
  void initSign() throws KeyczarException;

  /**
   * Update the signature with the given input.
   *
   * @param input The input to sign.
   * @throws KeyczarException If any Java JCE errors occur
   */
  void updateSign(ByteBuffer input) throws KeyczarException;

  /**
   * Sign the updated input and output the signature in the given buffer.
   *
   * @param output The output where the signature will be written.
   * @throws KeyczarException If any Java JCE errors occur or the output buffer
   *                          is too small.
   */
  void sign(ByteBuffer output) throws KeyczarException;

  /**
   * Return the size of the signature or digest in number of bytes.
   *
   * @return size of signature in bytes
   */
  int digestSize();
}