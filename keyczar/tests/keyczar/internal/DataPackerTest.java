package keyczar.internal;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class PackedDataOutputTest {
  static DataPacker output;
  static ByteArrayOutputStream outputStream;
  
  @Before
  public void setUp() throws Exception {
    outputStream = new ByteArrayOutputStream(100);
    output = new DataPacker(outputStream); 
  }
  
  @Test
  public final void testIntEncodingSize() {
    assertEquals(DataPacker.intEncodingSize(0), 1);
    assertEquals(DataPacker.intEncodingSize(127), 1);
    assertEquals(DataPacker.intEncodingSize(128), 2);
    assertEquals(DataPacker.intEncodingSize(32768), 3);
    assertEquals(DataPacker.intEncodingSize(-1), 5);
    assertEquals(DataPacker.intEncodingSize(-2), 5);
  }

  @Test
  public final void testLongEncodingSize() {
    assertEquals(DataPacker.longPackSize(0L), 1);
    assertEquals(DataPacker.longPackSize(127L), 1);
    assertEquals(DataPacker.longPackSize(128L), 2);
    assertEquals(DataPacker.longPackSize(32768L), 3);
    assertEquals(DataPacker.longPackSize((2L << 32)), 5);
    assertEquals(DataPacker.longPackSize((2L << 40)), 6);
    assertEquals(DataPacker.longPackSize(-1L), 10);
    assertEquals(DataPacker.longPackSize(-2L), 10);
  }

  @Test
  public final void testArrayEncodingSize() {
    assertEquals(DataPacker.arrayEncodingSize(new byte[0]), 1);
    assertEquals(DataPacker.arrayEncodingSize(new byte[1]), 2);
    assertEquals(DataPacker.arrayEncodingSize(new byte[128]), 130);
    assertEquals(DataPacker.arrayEncodingSize(new byte[32768]), 32771);
  }

  @Test
  public final void testPutInt() throws DataPackingException {
    byte[][] expected = {
        {0, 0},
        {0, 0, 8, -128, 1},
        {0, 0, 8, -128, 1, 16, -1, -1, -1, -1, 15}};
    output.putInt(0);
    byte[] test;
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[0]);
    output.putInt(128);
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[1]);
    output.putInt(-1);
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[2]);
  }

  @Test
  public final void testPutLong() throws DataPackingException {
    byte[][] expected = {
        {1, 0},
        {1, 0, 9, -128, 1},
        {1, 0, 9, -128, 1, 17, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1},
        {1, 0, 9, -128, 1, 17, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1,
          25, -128, -128, -128, -128, 32}};
    output.putLong(0);
    byte[] test;
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[0]);
    output.putLong(128);
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[1]);
    output.putLong(-1);
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[2]);
    output.putLong((2L << 32));
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[3]);
  }

  @Test
  public final void testPutArrayByteArray() throws DataPackingException {
    byte[][] expected = {
        {2, 3, 0, 1, 2},
        {2, 3, 0, 1, 2, 10, 1, 3}, 
        {2, 3, 0, 1, 2, 10, 1, 3, 18, 0}, 
        {2, 3, 0, 1, 2, 10, 1, 3, 18, 0, 26, 4, 4, 5, 6, 7},
    };
    output.putArray(new byte[]{0, 1, 2});
    byte[] test;
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[0]);
    output.putArray(new byte[]{3});
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[1]);
    output.putArray(new byte[0]);
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[2]);
    output.putArray(new byte[]{4, 5, 6, 7});
    test = outputStream.toByteArray();
    assertArrayEquals(test, expected[3]);
  }
  @Test
  public final void testPutMixed() throws DataPackingException {
    output.putInt(15);
    output.putArray(new byte[]{-32, 15});
    output.putLong(3);
    byte[] test = outputStream.toByteArray();
    byte[] expected = {0, 15, 10, 2, -32, 15, 17, 3};
    assertArrayEquals(test, expected);
  }
}
