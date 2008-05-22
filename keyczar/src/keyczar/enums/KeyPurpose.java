package keyczar.enums;

// TODO: Write JavaDocs
public enum KeyPurpose {
  DECRYPT_AND_ENCRYPT(0), ENCRYPT(1), SIGN_AND_VERIFY(2), TEST(127), VERIFY(3);

  private int value;

  private KeyPurpose(int v) {
    value = v;
  }

  int getValue() {
    return value;
  }

  static KeyPurpose getPurpose(int value) {
    switch (value) {
    case 0:
      return DECRYPT_AND_ENCRYPT;
    case 1:
      return ENCRYPT;
    case 2:
      return SIGN_AND_VERIFY;
    case 3:
      return VERIFY;
    case 255:
      return TEST;
    }
    return null;
  }
}
