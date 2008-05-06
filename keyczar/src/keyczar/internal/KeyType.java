package keyczar.internal;

enum KeyType {
  AES(0),
  HMAC_SHA1(1);

  private int value;
  private KeyType(int v) {
    this.value = v;
  }
    
  static KeyType getType(int value) {
    switch (value) {
      case 0: return AES;
      case 1: return HMAC_SHA1;
    }
    return null;
  }
    
  int getValue() {
    return value;
  }
}