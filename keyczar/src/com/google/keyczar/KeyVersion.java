// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.gson.annotations.Expose;
import com.google.keyczar.enums.KeyStatus;


// TODO: Write JavaDocs
class KeyVersion {
  @Expose private boolean exportable = false;
  @Expose private KeyStatus status = KeyStatus.ACTIVE;
  @Expose private int versionNumber = 0;

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

  boolean equals(KeyVersion v) {
    return getVersionNumber() == v.getVersionNumber()
        && getStatus() == v.getStatus() && isExportable() == v.isExportable();
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

  void setStatus(KeyStatus status) {
    this.status = status;
  }

  static KeyVersion read(String jsonString) {
    return Util.gson().fromJson(jsonString, KeyVersion.class);
  }
}
