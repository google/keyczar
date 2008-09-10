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

/**
 * Abstract class for KeyczarReaders. Typically, these will read key files from
 * disk, but may be implemented to read from arbitrary sources.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public interface KeyczarReader {
  /**
   * Returns an input stream of a particular version of a key
   *
   * @param version The Version number of the key to read
   * @return A JSON string data representation of a Key
   * @throws KeyczarException If an error occurs while attempting to read data,
   *         e.g. an IOException
   */
  String getKey(int version) throws KeyczarException;

  /**
   * @return A JSON string representation of KeyMetadata
   * @throws KeyczarException If an error occurs while attempting to read data,
   *         e.g. an IOException
   */
  String getMetadata() throws KeyczarException;
}