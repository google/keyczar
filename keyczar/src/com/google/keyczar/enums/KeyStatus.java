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

package com.google.keyczar.enums;

// TODO: Write JavaDocs
/**
 * Encodes different possible statuses of keys:
 *   Primary: This key can verify or decrypt existing data and can sign or 
 *   encrypt new data.
 *   Active:  This key can only verify or decrypt existing data.
 *   Scheduled for Revocation: This key can only verify or decrypt existing 
 *   data and may be revoked at any time.
 */
public enum KeyStatus {
  ACTIVE(1), PRIMARY(0), SCHEDULED_FOR_REVOCATION(2);

  private int value;

  private KeyStatus(int v) {
    value = v;
  }

  int getValue() {
    return value;
  }

  static KeyStatus getStatus(int value) {
    switch (value) {
    case 0:
      return PRIMARY;
    case 1:
      return ACTIVE;
    case 2:
      return SCHEDULED_FOR_REVOCATION;
    }
    return null;
  }
}
