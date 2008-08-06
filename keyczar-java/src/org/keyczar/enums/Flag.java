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
 * Flags supported by KeyczarTool.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public enum Flag {
  LOCATION("location"),
  NAME("name"),
  SIZE("size"),
  STATUS("status"),
  PURPOSE("purpose"),
  DESTINATION("destination"),
  VERSION("version"),
  ASYMMETRIC("asymmetric"),
  CRYPTER("crypter");

  private final String name;

  private Flag(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return name;
  }

  public static Flag getFlag(String name) {
    if (name == null) {
      throw new NullPointerException();
    }
    if (name.equalsIgnoreCase(LOCATION.toString())) {
      return LOCATION;
    } else if (name.equalsIgnoreCase(NAME.toString())) {
      return NAME;
    } else if (name.equalsIgnoreCase(SIZE.toString())) {
      return SIZE;
    } else if (name.equalsIgnoreCase(STATUS.toString())) {
      return STATUS;
    } else if (name.equalsIgnoreCase(PURPOSE.toString())) {
      return PURPOSE;
    } else if (name.equalsIgnoreCase(DESTINATION.toString())) {
      return DESTINATION;
    } else if (name.equalsIgnoreCase(VERSION.toString())) {
      return VERSION;
    } else if (name.equalsIgnoreCase(ASYMMETRIC.toString())) {
      return ASYMMETRIC;
    } else if (name.equalsIgnoreCase(CRYPTER.toString())) {
      return CRYPTER;
    }
    throw new IllegalArgumentException(
        Messages.getString("Flag.UnknownFlag", name));
  }
}