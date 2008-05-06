package keyczar.internal;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class DataPackerTest {
  static DataPacker output;
  static ByteArrayOutputStream outputStream;
  
  @Before
  public void setUp() throws Exception {
    outputStream = new ByteArrayOutputStream(100);
    output = new DataPacker(outputStream); 
  }
  
  @Test
  public final void testIntEncodingSize() {
    assertEquals(DataPacker.intPackSize(0), 1);
    assertEquals(DataPacker.intPackSize(127), 1);
    assertEquals(DataPacker.intPackSize(128), 2);
    assertEquals(DataPacker.intPackSize(32768), 3);
    assertEquals(DataPacker.intPackSize(-1), 5);
    assertEquals(DataPacker.intPackSize(-2), 5);
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
    assertEquals(DataPacker.arrayPackSize(new byte[0]), 1);
    assertEquals(DataPacker.arrayPackSize(new byte[1]), 2);
    assertEquals(DataPacker.arrayPackSize(new byte[128]), 130);
    assertEquals(DataPacker.arrayPackSize(new byte[32768]), 32771);
  }

  @Test
  public final void testPutInt() throws DataPackingException {
    byte[][] expected = {
        {8, 0},
        {8, 0, 16, -128, 1},
        {8, 0, 16, -128, 1, 24, -1, -1, -1, -1, 15}};
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
        {9, 0},
        {9, 0, 17, -128, 1},
        {9, 0, 17, -128, 1, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1},
        {9, 0, 17, -128, 1, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1,
          33, -128, -128, -128, -128, 32}};
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
        {10, 3, 0, 1, 2},
        {10, 3, 0, 1, 2, 18, 1, 3}, 
        {10, 3, 0, 1, 2, 18, 1, 3, 26, 0}, 
        {10, 3, 0, 1, 2, 18, 1, 3, 26, 0, 34, 4, 4, 5, 6, 7},
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
    byte[] expected = {8, 15, 18, 2, -32, 15, 25, 3};
    assertArrayEquals(test, expected);
  }
}
