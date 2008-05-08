package keyczar.internal;

public class Constants {
  private static final byte VERSION = 1;
  private static final int KEY_HASH_SIZE = 5;
  private static final int DIGEST_SIZE = 20;

  private Constants() {
    // Don't new me.
  }
  
  public static byte getVersion() { 
    return VERSION;
  }
  
  public static int getKeyHashSize() { 
    return KEY_HASH_SIZE;
  }
  
  public static int getDigestSize() {
    return DIGEST_SIZE;
  }
}
