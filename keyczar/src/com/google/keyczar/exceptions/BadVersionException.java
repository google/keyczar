// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar.exceptions;

public class BadVersionException extends KeyczarException {
  private static final long serialVersionUID = 7164364283899332453L;

  public BadVersionException(byte badVersion) {
    super("Received a bad version number: " + badVersion);
  }
}
