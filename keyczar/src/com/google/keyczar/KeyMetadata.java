// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.gson.annotations.Expose;
import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.enums.KeyType;

import java.util.ArrayList;
import java.util.List;

// TODO: Write JavaDocs
class KeyMetadata {
  @Expose private String name = "";
  @Expose private KeyPurpose purpose = KeyPurpose.TEST;
  @Expose private KeyType type = KeyType.TEST;
  @Expose private ArrayList<KeyVersion> versions = new ArrayList<KeyVersion>();

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

  boolean addVersion(KeyVersion version) {
    return versions.add(version);
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

  KeyVersion getVersion(int index) {
    return versions.get(index);
  }

  List<KeyVersion> getVersions() {
    return versions;
  }

  static KeyMetadata read(String jsonString) {
    return Util.gson().fromJson(jsonString, KeyMetadata.class);
  }
}
