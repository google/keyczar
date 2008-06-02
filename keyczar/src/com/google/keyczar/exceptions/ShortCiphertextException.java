// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class ShortCiphertextException extends KeyczarException {
  private static final long serialVersionUID = 7512790265291518499L;

  public ShortCiphertextException(int len) {
    super("Input of length " + len + " is too short to be valid ciphertext.");
  }
}
