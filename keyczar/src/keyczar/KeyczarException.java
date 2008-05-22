// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;


public class KeyczarException extends Exception {
  /**
   * 
   */
  private static final long serialVersionUID = 7893435087558002323L;

  public KeyczarException(String message) {
    super(message);
  }

  KeyczarException(String message, Throwable cause) {
    super(message, cause);
  }

  KeyczarException(Throwable cause) {
    super(cause);
  }
}


class BadVersionException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = 7164364283899332453L;

  BadVersionException(byte badVersion) {
    super("Received a bad version number: " + badVersion + " Expected: "
        + Keyczar.VERSION);
  }
}


class InvalidSignatureException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = -9209043556761224393L;

  InvalidSignatureException() {
    super("Invalid ciphertext signature");
  }
}


class KeyNotFoundException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = -2745196315795456118L;

  KeyNotFoundException(byte[] hash) {
    super("Key with hash identifier " + Integer.toHexString(Util.toInt(hash))
        + " not found");
  }
}


class NoPrimaryKeyException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = 2435853068538255446L;

  NoPrimaryKeyException() {
    super("No primary key found");
  }
}


class ShortBufferException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = -3056628233532649L;

  ShortBufferException(int given, int needed) {
    super("Short Buffer. Given " + given + " bytes. Need: " + needed);
  }
}


class ShortCiphertextException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = 7512790265291518499L;

  ShortCiphertextException(int len) {
    super("Input of length " + len + " is too short to be valid ciphertext.");
  }
}


class ShortSignatureException extends KeyczarException {
  /**
   * 
   */
  private static final long serialVersionUID = 4756259412053573790L;

  ShortSignatureException(int len) {
    super("Input of length " + len + " is too short to be valid signature.");
  }
}
