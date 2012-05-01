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

import org.keyczar.KeyczarKey;

import org.keyczar.exceptions.KeyczarException;

import java.util.List;

/**
 * The type of key, along with a list of acceptable (secure) key sizes.
 * 1
 *
 * @author jmscheiner@google.com (Justin Scheiner)
 */
public interface KeyType {

  /**
   * Returns the default (recommended) key size.
   *
   * @return default key size in bits
   */
  public int defaultSize();

  /**
   * @return the output size for the default key size
   */
  public int getOutputSize();

  /**
   * @param keySize the key size to get the output size for
   * @return the output size for the given key size
   */
  public int getOutputSize(int keySize);

  /**
   * Checks whether a given key size is acceptable.
   *
   * @param size integer key size
   * @return True if size is acceptable, False otherwise.
   */
  public boolean isAcceptableSize(int size);

  /**
   * @return a list of acceptable sizes for this key type
   */
  public List<Integer> getAcceptableSizes();

  /**
   * The value representing the key type when serialized.
   *
   * @return the integer value representing
   */
  public int getValue();

  /**
   * Creates {@link KeyczarKey}s from their serialized form or from scratch.
   *
   * TODO(jmscheiner): This bit of misdirection isn't necessary, but makes
   * backwards compatibility with the existing keys more straightforward.
   */
  public interface Builder {
    /**
     * Reads a {@link KeyczarKey} from its serialized form.
     *
     * @return the deserialized key
     * @throws KeyczarException if there is an issue deserializing the key
     */
    public KeyczarKey read(String s) throws KeyczarException;

    /**
     * Generates a key of this type, of the given size.
     *
     * @param keySize a valid key size, from {@link #getAcceptableSizes}.
     * @return a new {@link KeyczarKey}
     * @throws KeyczarException for key creation creation errors
     */
    public KeyczarKey generate(int keySize) throws KeyczarException;
  }

  /**
   * @return a reader for this key type
   */
  public Builder getBuilder();
}
