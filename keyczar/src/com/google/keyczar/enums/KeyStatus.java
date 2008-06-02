package com.google.keyczar.enums;

// TODO: Write JavaDocs
public enum KeyStatus {
  ACTIVE(1), PRIMARY(0), SCHEDULED_FOR_REVOCATION(2);

  private int value;

  private KeyStatus(int v) {
    value = v;
  }

  int getValue() {
    return value;
  }

  static KeyStatus getStatus(int value) {
    switch (value) {
    case 0:
      return PRIMARY;
    case 1:
      return ACTIVE;
    case 2:
      return SCHEDULED_FOR_REVOCATION;
    }
    return null;
  }
}
