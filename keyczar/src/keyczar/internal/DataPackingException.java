package keyczar.internal;

import java.io.IOException;

import keyczar.KeyczarException;

public class DataPackingException extends KeyczarException {
  DataPackingException(String message) {
    super(message);
  }
  
  DataPackingException(String message, Throwable cause) {
    super(message, cause);
  }

  DataPackingException(Throwable cause) {
    super(cause);
  }
}
