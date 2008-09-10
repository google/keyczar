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

package org.keyczar.enums;

import org.keyczar.i18n.Messages;

/**
 * Commands supported by KeyczarTool.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public enum Command {
  CREATE("create"),
  ADDKEY("addkey"),
  PUBKEY("pubkey"),
  PROMOTE("promote"),
  DEMOTE("demote"),
  REVOKE("revoke"),
  USEKEY("usekey");

  private final String name;

  private Command(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return name;
  }

  public static Command getCommand(String command) {
    if (command == null) {
      throw new NullPointerException();
    }
    if (command.equalsIgnoreCase(CREATE.toString())) {
      return CREATE;
    } else if (command.equalsIgnoreCase(ADDKEY.toString())) {
      return ADDKEY;
    } else if (command.equalsIgnoreCase(PUBKEY.toString())) {
      return PUBKEY;
    } else if (command.equalsIgnoreCase(PROMOTE.toString())) {
      return PROMOTE;
    } else if (command.equalsIgnoreCase(DEMOTE.toString())) {
      return DEMOTE;
    } else if (command.equalsIgnoreCase(REVOKE.toString())) {
      return REVOKE;
    } else if (command.equalsIgnoreCase(USEKEY.toString())) {
      return USEKEY;
    }
    throw new IllegalArgumentException(
        Messages.getString("Command.UnknownCommand", command));
  }
}