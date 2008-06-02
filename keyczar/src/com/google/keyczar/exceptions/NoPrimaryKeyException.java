// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class NoPrimaryKeyException extends KeyNotFoundException {
  private static final long serialVersionUID = 2435853068538255446L;

  public NoPrimaryKeyException() {
    super("No primary key found");
  }
}
