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

import org.json.JSONException;
import org.json.JSONObject;
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
public class KeyVersion {
  private boolean exportable = false;
  private KeyStatus status = KeyStatus.ACTIVE;
  private int versionNumber = 0;

  public KeyVersion(int v, boolean export) {
    this(v, KeyStatus.ACTIVE, export);
  }

  public KeyVersion(int v, KeyStatus s, boolean export) {
    versionNumber = v;
    status = s;
    exportable = export;
  }

  @Override
  public String toString() {
    return toJson().toString();
  }

  JSONObject toJson() {
    try {
      return new JSONObject()
          .put("versionNumber", versionNumber)
          .put("status", status != null ? status.name() : null)
          .put("exportable", exportable);
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
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

  public KeyStatus getStatus() {
    return status;
  }

  public int getVersionNumber() {
    return versionNumber;
  }

  public boolean isExportable() {
    return exportable;
  }

  /**
   * Updates the status of this KeyVersion to given status if not null.
   * @param status
   */
  public void setStatus(KeyStatus status) {
    this.status = (status == null) ? this.status : status;
  }

  public static KeyVersion read(String jsonString) {
    try {
      return fromJson(new JSONObject(jsonString));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  static KeyVersion fromJson(JSONObject json) throws JSONException {
    return new KeyVersion(
        json.getInt("versionNumber"),
        Util.deserializeEnum(KeyStatus.class, json.optString("status")),
        json.getBoolean("exportable"));
  }
}
