/*
 * Copyright 2013 Google Inc.
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

package org.keyczar.keyparams;

import org.keyczar.exceptions.KeyczarException;

/**
 * Interface for objects which provide key configuration parameters for key generation.
 * This base interface only provides one element, required by all keys: size.  Sub-interfaces
 * exist for specific key types that provide the configuration data they require.
 *
 * @author swillden
 */
public interface KeyParameters {

  /**
   * Returns desired key size, or -1 if unspecified.
   * @throws KeyczarException
   */
  public int getKeySize() throws KeyczarException;
}
