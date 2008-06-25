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

package com.google.keyczar.interfaces;

import com.google.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;


// JAVADOC
public interface SigningStream extends Stream {
  
  /**
   * Return the size of the signature or digest in number of bytes.
   * 
   * @return size of signature in bytes
   */
  int digestSize();

  // JAVADOC
  void initSign() throws KeyczarException;

  // JAVADOC
  void sign(ByteBuffer output) throws KeyczarException;

  // JAVADOC
  void updateSign(ByteBuffer input) throws KeyczarException;
}
