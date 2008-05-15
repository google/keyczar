package keyczar;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

// TODO: Write JavaDocs
class KeyMetadata {

  private final String name;
  private final KeyPurpose purpose;
  private final KeyType type;
  private final ArrayList<KeyVersion> versions = new ArrayList<KeyVersion>(); 

  KeyMetadata(String n, KeyPurpose p, KeyType t) {
    name = n;
    purpose = p;
    type = t;
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
  
  boolean addVersion(KeyVersion version) {
    return versions.add(version);
  }
  
  static KeyMetadata readJson(String jsonString) throws KeyczarException {
    try {
      JSONObject json = new JSONObject(jsonString);
      String n = json.getString("name");
      KeyPurpose p = KeyPurpose.getPurpose(json.getInt("purpose"));
      KeyType t = KeyType.getType(json.getInt("type"));
      JSONArray versions = json.getJSONArray("versions");
      KeyMetadata kmd = new KeyMetadata(n, p, t);
      for (int i = 0; i < versions.length(); i++) {
        kmd.addVersion(KeyVersion.read(versions.getString(i)));
      }
      return kmd;
    } catch (JSONException e) {
      throw new KeyczarException(e);
    }
  }

  List<KeyVersion> getVersions() {
    return versions;
  }
  
  @Override
  public String toString() {
    JSONObject json = new JSONObject();
    try {
      json.put("name", name);
      json.put("purpose", purpose.getValue());
      json.put("type", type.getValue());
      json.put("versions", versions);
    } catch (JSONException e) {
      // Do nothing? Will return empty JSON string
    }
    return json.toString();
  }
}
