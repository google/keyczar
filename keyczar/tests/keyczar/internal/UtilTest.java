package keyczar.internal;

import static org.junit.Assert.*;

import org.junit.Test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import keyczar.internal.Constants;
import keyczar.internal.Util;

public class UtilTest {
  // This is the expected SHA-1 hash of the empty string.
  private static final String emptyHash = 
    "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  private static final String dataHash = 
    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
  private static byte[] data = 
    "The quick brown fox jumps over the lazy dog".getBytes();
  private static byte[] dataStart = 
    "The quick brown fox".getBytes();
  private static byte[] dataEnd = 
    " jumps over the lazy dog".getBytes();
  
  private static String toHex(byte[] input) {
    return (new BigInteger(1, input)).toString(16);
  }

  @Test
  public final void testHashByteArrayIntIntByteArrayArray()
      throws GeneralSecurityException {
    byte[] output = new byte[20];
    Util.hash(output, 0, output.length);
    assertEquals(emptyHash, toHex(output));
    Util.hash(output, 0, output.length, data);
    assertEquals(dataHash, toHex(output));
  }

  @Test
  public final void testHashByteArrayArray() {
    assertEquals(emptyHash, toHex(Util.hash()));
    assertEquals(dataHash, toHex(Util.hash(data)));
    // Try hashing in several chunks
    assertEquals(dataHash, toHex(Util.hash(dataStart,
        new byte[0], dataEnd, new byte[0])));
  }

  @Test
  public final void testIntConversions() {
    // This tests fromInt, writeInt, toInt, and readInt
    assertEquals(Util.toInt(Util.fromInt(0)), 0);
    assertEquals(Util.toInt(Util.fromInt(1)), 1);
    assertEquals(Util.toInt(Util.fromInt(-1)), -1);
    assertEquals(Util.toInt(Util.fromInt(0xF0F0F0F0)), 0xF0F0F0F0);
    assertEquals(Util.toInt(Util.fromInt(0xCA0880AC)), 0xCA0880AC);
    assertEquals(Util.toInt(Util.fromInt(0x12345678)), 0x12345678);
  }

  @Test
  public final void testLongConversions() {
    // This tests fromLong, writeLong, toLong, and readLong
    assertEquals(Util.toLong(Util.fromLong(0)), 0);
    assertEquals(Util.toLong(Util.fromLong(1)), 1);
    assertEquals(Util.toLong(Util.fromLong(-1)), -1);
    assertEquals(Util.toLong(Util.fromLong(-1L)), -1L);
    assertEquals(Util.toLong(Util.fromLong(0xF0F0F0F0F0F0F0F0L)),
        0xF0F0F0F0F0F0F0F0L);
    assertEquals(Util.toLong(Util.fromLong(0xCA0880AC3A5BB78L)), 
        0xCA0880AC3A5BB78L);
    assertEquals(Util.toLong(Util.fromLong(0x123456789ABCDEF0L)),
        0x123456789ABCDEF0L);
  }
}
