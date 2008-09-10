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


/**
 * Base class of all possible exceptions thrown by Keyczar.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class KeyczarException extends Exception {
  private static final long serialVersionUID = 7893435087558002323L;

  public KeyczarException(String message) {
    super(message);
  }

  public KeyczarException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyczarException(Throwable cause) {
    super(cause);
  }
}