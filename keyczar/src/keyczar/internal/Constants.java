package keyczar.internal;

public class Constants {
  public static final byte VERSION = 1;
  public static final int KEY_HASH_SIZE = 4;
  public static final int HEADER_SIZE = 1 + KEY_HASH_SIZE;
  public static final byte[] VERSION_ARRAY = { VERSION };
  private Constants() {
    // Don't new me.
  }
}
