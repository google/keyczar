// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class InvalidSignatureException extends KeyczarException {
  private static final long serialVersionUID = -9209043556761224393L;

  public InvalidSignatureException() {
    super("Invalid ciphertext signature");
  }
}
