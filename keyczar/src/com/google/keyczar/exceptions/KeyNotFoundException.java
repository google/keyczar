// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class KeyNotFoundException extends KeyczarException {
  private static final long serialVersionUID = -2745196315795456118L;

  public KeyNotFoundException(byte[] hash) {
    super("Key with hash identifier " +
        Integer.toHexString(((hash[0] & 0xFF) << 24) | ((hash[1] & 0xFF) << 16) |
                            ((hash[2] & 0xFF) << 8) | ((hash[3] & 0xFF)))
        + " not found");
  }

  KeyNotFoundException(String string) {
    super(string);
  }
}
