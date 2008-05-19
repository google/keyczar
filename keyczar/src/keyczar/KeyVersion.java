package keyczar;

import com.google.gson.annotations.Expose;


// TODO: Write JavaDocs
class KeyVersion {
  @Expose private int versionNumber = 0;
  @Expose private KeyStatus status = KeyStatus.ACTIVE;
  @Expose private boolean exportable = false;
  
  private KeyVersion() {
    // For Gson
  }
  
  KeyVersion(int v, KeyStatus s, boolean export) {
    versionNumber = v;
    status = s;
    exportable = export;
  }
  
  KeyVersion(int v, boolean export) {
    this(v, KeyStatus.ACTIVE, export);
  }

  int getVersionNumber() {
    return versionNumber;
  }
  
  KeyStatus getStatus() {
    return status;
  }
  
  boolean isExportable() {
    return exportable;
  }
  
  boolean equals(KeyVersion v) {
    return this.getVersionNumber() == v.getVersionNumber() &&
      this.getStatus() == v.getStatus() &&
      this.isExportable() == v.isExportable();
  }

  void setStatus(KeyStatus status) {
    this.status = status;
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  public static KeyVersion read(String jsonString) {
    return Util.gson().fromJson(jsonString, KeyVersion.class);
  }
}
