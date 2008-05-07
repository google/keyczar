package keyczar;

import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;

class KeyVersion {
  private final int versionNumber;
  private KeyStatus status;
  private final boolean exportable;
  
  KeyVersion(int v, KeyStatus s, boolean export) {
    this.versionNumber = v;
    this.status = s;
    this.exportable = export;
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

  static KeyVersion getVersion(DataUnpacker unpacker)
      throws DataPackingException {
    int v = unpacker.getInt();
    KeyStatus s = KeyStatus.getStatus(unpacker.getInt());
    int b = unpacker.getInt();
    return new KeyVersion(v, s, (b != 0));
  }

  int write(DataPacker packer) throws DataPackingException {
    int written = packer.putInt(versionNumber);
    written += packer.putInt(status.getValue());
    written += packer.putInt(exportable ? 1 : 0);
    return written;
  }

  void setStatus(KeyStatus status) {
    this.status = status;
  }
  
  @Override
  public String toString() {
    StringBuffer buffer = new StringBuffer("Version: ");
    buffer.append(getVersionNumber());
    buffer.append(" Status: ").append(getStatus());
    if (exportable) {
      buffer.append(" Exportable");
    }
    return buffer.toString();
  }
}
