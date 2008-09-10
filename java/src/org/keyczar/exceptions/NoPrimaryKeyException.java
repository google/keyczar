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
 * Primary key is missing when trying to perform an operation
 * (e.g. decrypt, sign) that requires a primary key.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class NoPrimaryKeyException extends KeyNotFoundException {
  private static final long serialVersionUID = 2435853068538255446L;

  public NoPrimaryKeyException() {
    super(Messages.getString("NoPrimaryKeyFound"));
  }
}