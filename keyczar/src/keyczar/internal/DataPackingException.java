package keyczar.internal;

public class DataPackingException extends Exception {

  DataPackingException(String message) {
    super(message);
  }

  public DataPackingException(Throwable e) {
    super(e);
  }
  
  public DataPackingException(String message, Throwable e) {
    super(message, e);
  }
}
