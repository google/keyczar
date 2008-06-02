// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class KeyczarException extends Exception {
  private static final long serialVersionUID = 7893435087558002323L;

  public KeyczarException(String message) {
    super(message);
  }

  public KeyczarException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyczarException(Throwable cause) {
    super(cause);
  }
}