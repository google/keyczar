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

package org.keyczar;

import com.google.gson.annotations.Expose;

import org.keyczar.enums.KeyStatus;
import org.keyczar.util.Util;


/**
 * A key version consists of the following:
 * <ul>
 *   <li>an integer value version number, counting from 1,
 *   <li>a KeyStatus, and
 *   <li>a boolean representing whether this key is exportable
 *       outside of Keyczar.
 * </ul>
 * <p>JSON Representation consists of the following fields:
 * <ul>
 *   <li>"status": JSON representation of KeyStatus value,
 *   <li>"versionNumber": integer version number,
 *   <li>"exportable": boolean value.
 * </ul>
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
class KeyVersion {
  @Expose private boolean exportable = false;
  @Expose private KeyStatus status = KeyStatus.ACTIVE;
  @Expose private int versionNumber = 0;

  @SuppressWarnings("unused")
  private KeyVersion() {
    // For GSON
  }

  KeyVersion(int v, boolean export) {
    this(v, KeyStatus.ACTIVE, export);
  }

  KeyVersion(int v, KeyStatus s, boolean export) {
    versionNumber = v;
    status = s;
    exportable = export;
  }

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof KeyVersion)) {
      return false;
    }
    KeyVersion v = (KeyVersion) o;
    return getVersionNumber() == v.getVersionNumber();
    // only depend on version number, otherwise changing status changes identity
  }

  @Override
  public int hashCode() {
    return versionNumber; // identity depends only on version number
  }

  KeyStatus getStatus() {
    return status;
  }

  int getVersionNumber() {
    return versionNumber;
  }

  boolean isExportable() {
    return exportable;
  }

  /**
   * Updates the status of this KeyVersion to given status if not null.
   * @param status
   */
  void setStatus(KeyStatus status) {
    this.status = (status == null) ? this.status : status;
  }

  static KeyVersion read(String jsonString) {
    return Util.gson().fromJson(jsonString, KeyVersion.class);
  }
}
