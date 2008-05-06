package keyczar.internal;

class KeyVersion {
  private final int versionNumber;
  private final KeyStatus status;
  private final boolean exportable;
  
  KeyVersion(int v, KeyStatus s, boolean export) {
    this.versionNumber = v;
    this.status = s;
    this.exportable = export;
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
}
