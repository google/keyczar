package keyczar;

enum KeyPurpose {
  DECRYPT_AND_ENCRYPT(0),
  ENCRYPT(1),
  SIGN_AND_VERIFY(2),
  VERIFY(3),
  TEST(127);
  
  private int value;
  private KeyPurpose(int v) {
    this.value = v;
  }
           
  static KeyPurpose getPurpose(int value) {
    switch (value) {
      case 0: return DECRYPT_AND_ENCRYPT;
      case 1: return ENCRYPT;
      case 2: return SIGN_AND_VERIFY;
      case 3: return VERIFY;
      case 255: return TEST;
    }
    return null;
  }
  
  int getValue() {
    return value;
  }
}