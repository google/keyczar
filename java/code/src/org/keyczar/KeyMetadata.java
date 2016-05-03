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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.interfaces.KeyType;
import org.keyczar.util.Util;
import org.keyczar.exceptions.NoPrimaryKeyException;

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
public class KeyMetadata {
  String name = "";
  KeyPurpose purpose = KeyPurpose.TEST;
  KeyType type = DefaultKeyType.TEST;
  List<KeyVersion> versions = new ArrayList<KeyVersion>();
  boolean encrypted = false;

  protected Map<Integer, KeyVersion> versionMap =
      new HashMap<Integer, KeyVersion>(); // link version number to version

  public KeyMetadata(String n, KeyPurpose p, KeyType t) {
    name = n;
    purpose = p;
    type = t;
  }

  private KeyMetadata(String name, KeyPurpose purpose, KeyType type,
      List<KeyVersion> versions, boolean encrypted) {
    this.name = name;
    this.purpose = purpose;
    this.type = type;
    this.versions = versions;
    this.encrypted = encrypted;
  }

  @Override
  public String toString() {
    try {
      return new JSONObject()
          .put("name", name)
          .put("purpose", purpose != null ? purpose.name() : null)
          .put("type", type != null ? type.getName() : null)
          .put("versions", keyVersionsToJson())
          .put("encrypted", encrypted)
          .toString();
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  private JSONArray keyVersionsToJson() {
    JSONArray jsonArray = new JSONArray();
    int max = versions.size();
    for (int i = 0; i < max; i++) {
      jsonArray.put(versions.get(i).toJson());
    }
    return jsonArray;
  }

  /**
   * Adds given key version to key set.
   *
   * @param version KeyVersion of key to be added
   * @return true if add was successful, false if version number collides
   */
  public boolean addVersion(KeyVersion version) {
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
  public boolean removeVersion(int versionNumber) {
    if (versionMap.containsKey(versionNumber)) {
      KeyVersion version = versionMap.get(versionNumber);
      versions.remove(version);
      versionMap.remove(versionNumber);
      return true;
    }
    return false;
  }

  public String getName() {
    return name;
  }

  public KeyPurpose getPurpose() {
    return purpose;
  }

  public KeyType getType() {
    return type;
  }

  void setType(KeyType type) {
    this.type = type;
  }

  void setEncrypted(boolean encrypted) {
    this.encrypted = encrypted;
  }

  public boolean isEncrypted() {
    return encrypted;
  }

  /**
   * Returns the version corresponding to the version number.
   *
   * @param versionNumber
   * @return KeyVersion corresponding to given number, or null if nonexistent
   */
  public KeyVersion getVersion(int versionNumber) {
    return versionMap.get(versionNumber);
  }

  public List<KeyVersion> getVersions() {
    return versions;
  }

  public KeyVersion getPrimaryVersion() throws NoPrimaryKeyException {
    for (KeyVersion version : versions) {
      if (version.getStatus() == KeyStatus.PRIMARY) {
	    return version;
	  }
    }
		
    throw new NoPrimaryKeyException();
  }

  /**
   * Parses JSON string to create a KeyMetadata object. Initializes it with
   * versions listed in the JSON array.
   *
   * @param jsonString
   * @return KeyMetadata corresponding to JSON input
   */
  public static KeyMetadata read(String jsonString) {
    try {
      JSONObject json = new JSONObject(jsonString);
      KeyMetadata kmd = new KeyMetadata(
          json.getString("name"),
          Util.deserializeEnum(KeyPurpose.class, json.optString("purpose")),
          new KeyType.KeyTypeDeserializer().deserialize(json.getString("type")),
          buildVersions(json.getJSONArray("versions")),
          json.getBoolean("encrypted"));
      for (KeyVersion version : kmd.getVersions()) {
        kmd.versionMap.put(version.getVersionNumber(), version);
      }
      return kmd;
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  private static List<KeyVersion> buildVersions(JSONArray jsonArray) throws JSONException {
    List<KeyVersion> list = new ArrayList<KeyVersion>();
    int max = jsonArray.length();
    for (int i = 0; i < max; i++) {
      list.add(KeyVersion.fromJson(jsonArray.getJSONObject(i)));
    }
    return list;
  }
}
