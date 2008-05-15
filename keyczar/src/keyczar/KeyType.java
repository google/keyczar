package keyczar;

// TODO: Write JavaDocs
enum KeyType {
  AES(0, 16),
  HMAC_SHA1(1, 32),
  TEST(127, 1);

  private int value;
  private int defaultSize;
  private KeyType(int v, int defaultSize) {
    this.value = v;
    this.defaultSize = defaultSize;
  }
    
  static KeyType getType(int value) {
    switch (value) {
      case 0: return AES;
      case 1: return HMAC_SHA1;
      case 127: return TEST;
    }
    return null;
  }
  
  int defaultSize() {
    return defaultSize;
  }
    
  int getValue() {
    return value;
  }
}