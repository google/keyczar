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

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyType;
import org.keyczar.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Encodes metadata for a set of keys which consists of the following:
 * <ul>
 *   <li>a string-valued name,
 *   <li>a KeyPurpose,
 *   <li>a KeyType, and
 *   <li>a set of KeyVersion values.
 * </ul>
 *
 * <p>JSON Representation consists of the following fields:
 * <ul>
 *   <li>"name": a String name,
 *   <li>"purpose": JSON representation of KeyPurpose value,
 *   <li>"type": JSON representation of KeyType value,
 *   <li>"versions": JSON representation of an array of KeyVersion values.
 * </ul>
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
class KeyMetadata {
  @Expose String name = "";
  @Expose KeyPurpose purpose = KeyPurpose.TEST;
  @Expose KeyType type = KeyType.TEST;
  @Expose List<KeyVersion> versions = new ArrayList<KeyVersion>();
  @Expose boolean encrypted = false;

  protected Map<Integer, KeyVersion> versionMap =
      new HashMap<Integer, KeyVersion>(); // link version number to version

  @SuppressWarnings("unused")
  private KeyMetadata() {
    // For GSON
  }

  KeyMetadata(String n, KeyPurpose p, KeyType t) {
    name = n;
    purpose = p;
    type = t;
  }

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  /**
   * Adds given key version to key set.
   *
   * @param version KeyVersion of key to be added
   * @return true if add was successful, false if version number collides
   */
  boolean addVersion(KeyVersion version) {
    int versionNumber = version.getVersionNumber();
    if (!versionMap.containsKey(versionNumber)) {
      versionMap.put(versionNumber, version);
      versions.add(version);
      return true;
    }
    return false;
  }

  /**
   * Removes given key version from key set.
   *
   * @param versionNumber integer version number of key to be removed
   * @return true if remove was successful
   */
  boolean removeVersion(int versionNumber) {
    if (versionMap.containsKey(versionNumber)) {
      KeyVersion version = versionMap.get(versionNumber);
      versions.remove(version);
      versionMap.remove(versionNumber);
      return true;
    }
    return false;
  }

  String getName() {
    return name;
  }

  KeyPurpose getPurpose() {
    return purpose;
  }

  KeyType getType() {
    return type;
  }

  void setEncrypted(boolean encrypted) {
    this.encrypted = encrypted;
  }

  boolean isEncrypted() {
    return encrypted;
  }

  /**
   * Returns the version corresponding to the version number.
   *
   * @param versionNumber
   * @return KeyVersion corresponding to given number, or null if nonexistent
   */
  KeyVersion getVersion(int versionNumber) {
    return versionMap.get(versionNumber);
  }

  List<KeyVersion> getVersions() {
    return versions;
  }

  /**
   * Parses JSON string to create a KeyMetadata object. Initializes it with
   * versions listed in the JSON array.
   *
   * @param jsonString
   * @return KeyMetadata corresponding to JSON input
   */
  static KeyMetadata read(String jsonString) {
    KeyMetadata kmd = Util.gson().fromJson(jsonString, KeyMetadata.class);
    for (KeyVersion version : kmd.getVersions()) {
      kmd.versionMap.put(version.getVersionNumber(), version);
    }
    return kmd;
  }
}
