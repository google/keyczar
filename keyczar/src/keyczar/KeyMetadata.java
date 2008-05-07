package keyczar;

import java.util.ArrayList;
import java.util.List;

import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;

class KeyMetadata {

  private final String name;
  private final KeyPurpose purpose;
  private final KeyType type;
  private final ArrayList<KeyVersion> versions = new ArrayList<KeyVersion>(); 
  
  KeyMetadata(String n, KeyPurpose p, KeyType t) {
    this.name = n;
    this.purpose = p;
    this.type = t;
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

  static KeyMetadata getMetadata(DataUnpacker unpacker)
      throws DataPackingException {
    String name = new String(unpacker.getArray());
    KeyPurpose p = KeyPurpose.getPurpose(unpacker.getInt());
    KeyType t = KeyType.getType(unpacker.getInt());
    KeyMetadata kmd = new KeyMetadata(name, p, t);
    int numVersions = unpacker.getInt();
    for (int i = 0; i < numVersions; i++) 
      kmd.addVersion(KeyVersion.getVersion(unpacker));
    return kmd;
  }
  
  int write(DataPacker packer) throws DataPackingException {
    int written = packer.putArray(name.getBytes());
    written += packer.putInt(purpose.getValue());
    written += packer.putInt(type.getValue());
    written += packer.putInt(versions.size());
    for (KeyVersion v : versions) {
      written += v.write(packer);
    }
    return written;
  }

  List<KeyVersion> getVersions() {
    return versions;
  }
  
  @Override
  public String toString() {
    StringBuffer buffer = new StringBuffer(name);
    buffer.append(" Purpose: ").append(getPurpose());
    buffer.append(" Type: ").append(getType());
    buffer.append(" Versions: ").append(getVersions().size());
    return buffer.toString();
  }
}
