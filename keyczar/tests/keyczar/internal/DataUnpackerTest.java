package keyczar.internal;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;

public class DataUnpackerTest {
  static DataUnpacker input;
  static ByteArrayInputStream inputStream;
  
  @Test
  public final void testGetInt() throws DataPackingException {
    inputStream = new ByteArrayInputStream(
        new byte[]{0, 0, 8, -128, 1, 16, -1, -1, -1, -1, 15});
    input = new DataUnpacker(inputStream);
    assertEquals(input.getInt(), 0);
    assertEquals(input.getInt(), 128);
    assertEquals(input.getInt(), -1);
    
  }

  @Test
  public final void testGetLong() throws DataPackingException {
    inputStream = new ByteArrayInputStream(
        new byte[]{1, 0, 9, -128, 1, 17, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, 1, 25, -128, -128, -128, -128, 32});
    input = new DataUnpacker(inputStream);
    assertEquals(input.getLong(), 0);
    assertEquals(input.getLong(), 128);
    assertEquals(input.getLong(), -1);
    assertEquals(input.getLong(), (2L <<32));
  }

  @Test
  public final void testGetArray() throws DataPackingException {
    inputStream = new ByteArrayInputStream(
        new byte[]{2, 3, 0, 1, 2, 10, 1, 3, 18, 0, 26, 4, 4, 5, 6, 7});
    input = new DataUnpacker(inputStream);
    byte[][] testArrays = {{0, 1, 2}, {3}, {}, {4, 5, 6, 7}};
    for (byte[] test : testArrays) 
      assertArrayEquals(input.getArray(), test);
  }
}
