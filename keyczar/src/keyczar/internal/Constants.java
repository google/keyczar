package keyczar.internal;

public class Constants {
  private static final byte VERSION = 1;
  private static final int HEADER_SIZE = 5;
  private static final int DIGEST_SIZE = 20;

  private Constants() {
    // Don't new me.
  }
  
  public static byte getVersion() { 
    return VERSION;
  }
  
  public static int getHeaderSize() { 
    return HEADER_SIZE;
  }
  
  public static int getDigestSize() {
    return DIGEST_SIZE;
  }
}
