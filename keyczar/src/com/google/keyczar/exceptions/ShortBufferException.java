// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class ShortBufferException extends KeyczarException {
  private static final long serialVersionUID = -3056628233532649L;

  public ShortBufferException(int given, int needed) {
    super("Short Buffer. Given " + given + " bytes. Need: " + needed);
  }
  
  public ShortBufferException(Throwable cause) {
    super(cause);
  }
}
