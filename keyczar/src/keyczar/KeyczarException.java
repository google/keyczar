package keyczar;

import java.io.FileNotFoundException;

public class KeyczarException extends Exception {
  public KeyczarException(String message) {
    super(message);
  }

  public KeyczarException(String message, Throwable cause) {
    super(message, cause);
  }
}
