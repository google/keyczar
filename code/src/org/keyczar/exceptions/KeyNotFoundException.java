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

package org.keyczar.exceptions;

import org.keyczar.i18n.Messages;

/**
 * Key with a particular hash is not found.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class KeyNotFoundException extends KeyczarException {
  private static final long serialVersionUID = -2745196315795456118L;

  public KeyNotFoundException(byte[] hash) {
    super(Messages.getString("KeyWithHashIdentifier",
        Integer.toHexString(((hash[0] & 0xFF) << 24) | ((hash[1] & 0xFF) << 16)
                            | ((hash[2] & 0xFF) << 8) | ((hash[3] & 0xFF)))));
  }

  KeyNotFoundException(String string) {
    super(string);
  }
}