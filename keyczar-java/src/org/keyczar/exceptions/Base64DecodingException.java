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
 * An error occurs in attempting to decode a web-safe Base64 string
 * (e.g. bad characters not in the alphabet, bad padding).
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Base64DecodingException extends KeyczarException {
  public Base64DecodingException(Throwable cause) {
    super(cause);
  }

  public Base64DecodingException(String string) {
    super(string);
  }
}