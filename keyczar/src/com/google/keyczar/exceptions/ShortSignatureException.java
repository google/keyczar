// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class ShortSignatureException extends KeyczarException {
  private static final long serialVersionUID = 4756259412053573790L;

  public ShortSignatureException(int len) {
    super("Input of length " + len + " is too short to be valid signature.");
  }
}
