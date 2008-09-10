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
 * Verifying Streams are able to verify data that has been signed by
 * {@link SigningStream} objects.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public interface VerifyingStream extends Stream {
  /**
   * @return The size of digests that this stream will verify.
   */
  int digestSize();

  /**
   * Initialize this stream for verification. This must be called before
   * updateVerify().
   *
   * @throws KeyczarException If a Java JCE error occurs.
   */
  void initVerify() throws KeyczarException;

  /**
   * Update the data which has been signed.
   *
   * @param input Data which has been signed.
   * @throws KeyczarException If a Java JCE error occurs.
   */
  void updateVerify(ByteBuffer input) throws KeyczarException;

  /**
   * Verify that the given signautre is a valid signautre on the updated data.
   * @param signature The signature to verify
   * @return Whether the given signature is valid.
   * @throws KeyczarException If a Java JCE error occurs.
   */
  boolean verify(ByteBuffer signature) throws KeyczarException;
}