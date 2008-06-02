package com.google.keyczar.enums;

import com.google.gson.annotations.Expose;

// TODO: Write JavaDocs
public enum KeyType {
  AES(0, 128, 0), DSA_PRIV(2, 1024, 48), DSA_PUB(3, 1024, 48), HMAC_SHA1(1,
      256, 20), RSA_PRIV(4, 2048, 256), RSA_PUB(5, 2048, 256), TEST(127, 1, 0);

  private int defaultSize;
  private int outputSize;
  @Expose
  private int value;

  private KeyType(int v, int defaultSize, int outputSize) {
    value = v;
    this.defaultSize = defaultSize;
    this.outputSize = outputSize;
  }

  // Returns default size in bits
  public int defaultSize() {
    return defaultSize;
  }

  public int getOutputSize() {
    return outputSize;
  }

  int getValue() {
    return value;
  }

  static KeyType getType(int value) {
    switch (value) {
    case 0:
      return AES;
    case 1:
      return HMAC_SHA1;
    case 2:
      return DSA_PRIV;
    case 3:
      return DSA_PUB;
    case 4:
      return DSA_PRIV;
    case 5:
      return DSA_PUB;
    case 127:
      return TEST;
    }
    return null;
  }
}
