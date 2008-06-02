package com.google.keyczar.exceptions;

public class Base64DecodingException extends KeyczarException {
  public Base64DecodingException(Throwable cause) {
    super(cause);
  }

  public Base64DecodingException(String string) {
    super(string);
  }
}
