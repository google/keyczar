package keyczar;

import org.json.JSONException;
import org.json.JSONObject;

// TODO: Write JavaDocs
class KeyVersion {
  private final int versionNumber;
  private KeyStatus status;
  private final boolean exportable;
  
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
    JSONObject json = new JSONObject();
    try {
      json.put("number", versionNumber);
      json.put("status", status.getValue());
      json.put("exportable", exportable);
    } catch (JSONException e) {
      // Do nothing? Returns empty JSON string
    }
    return json.toString();
  }

  public static KeyVersion read(String jsonString) throws KeyczarException {
    try {
      JSONObject json = new JSONObject(jsonString);
      int v = json.getInt("number");
      KeyStatus s = KeyStatus.getStatus(json.getInt("status"));
      boolean export = json.getBoolean("exportable");
      return new KeyVersion(v, s, export);
    } catch (JSONException e) {
      throw new KeyczarException(e);
    }
  }
}
