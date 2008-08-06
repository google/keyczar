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


import org.keyczar.enums.KeyType;
import org.keyczar.i18n.Messages;

/**
 * A key type was used in an inappropriate purpose.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class UnsupportedTypeException extends KeyczarException {
  public UnsupportedTypeException(KeyType type) {
    super(Messages.getString("InvalidTypeInInput", type));
  }

}