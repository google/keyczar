package keyczar.internal;

public enum PackedDataType {
  INT((byte) 0),
  LONG((byte) 1),
  ARRAY((byte) 2);
    
  private byte value;
  private PackedDataType(byte b) {
    this.value = b;
  }
    
  static PackedDataType fromByte(byte b) {
    switch (b) {
      case 0:
        return INT;
      case 1:
        return LONG;
      case 2:
        return ARRAY;
    }
    return null;
  }
    
  byte getValue() {
    return value;
  }
  
  byte getLabel(int count) {
    return (byte) (count << 3 | value);
  }
}
