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
 * Keyczar output that is not properly prepended by the current Keyczar version
 * is parsed.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class BadVersionException extends KeyczarException {
  private static final long serialVersionUID = 7164364283899332453L;

  public BadVersionException(byte badVersion) {
    super(Messages.getString("BadVersionNumber", badVersion));
  }
}