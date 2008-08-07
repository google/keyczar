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

/**
 * Encodes different possible statuses of keys:
 * <ul>
 *   <li>Primary: This key can verify or decrypt existing data and can sign or 
 *   encrypt new data.
 *   <li>Active:  This key can only verify or decrypt existing data.
 *   <li>Inactive: This key can only verify or decrypt existing 
 *   data and may be revoked at any time.
 * </ul>
 * 
 * <p>JSON Representation is one of the strings:
 * <ul>
 *   <li>"PRIMARY"
 *   <li>"ACTIVE"
 *   <li>"INACTIVE"
 * </ul>
 * 
 *  @author steveweis@gmail.com (Steve Weis)
 *  @author arkajit.dey@gmail.com (Arkajit Dey)
 *  
 */
public enum KeyStatus {
  PRIMARY(0, "primary"), 
  ACTIVE(1, "active"),
  INACTIVE(2, "inactive");

  private int value;
  private String name;

  private KeyStatus(int v, String s) {
    value = v;
    name = s;
  }

  int getValue() {
    return value;
  }
  
  String getName() {
    return name;
  }
  
  public static KeyStatus getStatus(int value) {
    switch (value) {
      case 0:
        return PRIMARY;
      case 1:
        return ACTIVE;
      case 2:
        return INACTIVE;
    }
    return null;
  }
  
  public static KeyStatus getStatus(String name) {
    if (name != null) {
      if (name.equalsIgnoreCase(PRIMARY.getName())) {
        return PRIMARY;
      } else if (name.equalsIgnoreCase(ACTIVE.getName())) {
        return ACTIVE;
      } else if (name.equalsIgnoreCase(INACTIVE.getName())) {
        return INACTIVE;
      }
    }
    return ACTIVE; // default status
  }
}