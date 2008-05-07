// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.FileNotFoundException;

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
