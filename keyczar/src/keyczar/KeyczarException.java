// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.FileNotFoundException;

import keyczar.internal.Constants;
import keyczar.internal.Util;

public class KeyczarException extends Exception {
  protected KeyczarException(String message) {
    super(message);
  }

  protected KeyczarException(String message, Throwable cause) {
    super(message, cause);
  }
  
  protected KeyczarException(Throwable cause) {
    super(cause);
  }
}

class InvalidSignatureException extends KeyczarException {
  protected InvalidSignatureException() {
    super("Invalid ciphertext signature");
  }
}

class NoPrimaryKeyException extends KeyczarException {
  protected NoPrimaryKeyException() {
    super("No primary key found");
  }
}

class ShortBufferException extends KeyczarException {
  protected ShortBufferException(int given, int needed) {
    super("Short Buffer. Given " + given + " bytes. Need: " + needed);
  }
}

class KeyNotFoundException extends KeyczarException {
  protected KeyNotFoundException(byte[] hash) {
    super("Key with hash identifier " + Integer.toHexString(Util.toInt(hash)) +
        " not found");
  }
}

class ShortCiphertextException extends KeyczarException {
  protected ShortCiphertextException(int len) {
    super("Input of length " + len + " is too short to be valid ciphertext.");
  }
}

class ShortSignatureException extends KeyczarException {
  protected ShortSignatureException(int len) {
    super("Input of length " + len + " is too short to be valid signature.");
  }
}

class BadVersionException extends KeyczarException {
  protected BadVersionException(byte badVersion) {
    super("Received a bad version number: " + badVersion + " Expected: " +
        Constants.VERSION);
  }
}