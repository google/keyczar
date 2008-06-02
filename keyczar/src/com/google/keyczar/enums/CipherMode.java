// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.enums;

import com.google.gson.annotations.Expose;

public enum CipherMode {
  CBC(0, "AES/CBC/PKCS5Padding", true),
  CTR(1, "AES/CTR/NoPadding", true),
  ECB(2, "AES/ECB/NoPadding", false),
  DET_CBC(3, "AES/CBC/PKCS5Padding", false); 

  private String jceMode;
  @Expose
  private int value;

  private CipherMode(int v, String s, boolean useIv) {
    value = v;
    jceMode = s;
  }

  public String getMode() {
    return jceMode;
  }

  int getValue() {
    return value;
  }

  static CipherMode getMode(int value) {
    switch (value) {
    case 0:
      return CBC;
    case 1:
      return CTR;
    case 2:
      return ECB;
    case 3:
      return DET_CBC;
    }
    return null;
  }
}
