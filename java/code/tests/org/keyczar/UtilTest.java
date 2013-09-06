package org.keyczar;

import junit.framework.TestCase;

import java.nio.ByteBuffer;

import org.keyczar.util.Util;

/**
 * Test cases for the org.keyczar.util.Util methods
 * 
 * TODO(dlundberg): Create test cases for all of the Util methods.
 */
public class UtilTest extends TestCase {

  private void doTestBadLenPrefixUnpack(byte[] input, int maxLength) {
    byte[][] output = Util.lenPrefixUnpack(input, maxLength);
    assertNull(output);
  }
  
  private void doTestGoodLenPrefixUnpack(int numArrays, int arrayLength) {
    ByteBuffer buff = ByteBuffer.allocate(numArrays * arrayLength + 4 * numArrays + 4);
    buff.putInt(numArrays);
    for (int i = 0; i < numArrays; i++) {
      buff.putInt(arrayLength);
      for (int j = 0; j < arrayLength; j++) {
        buff.put((byte) 0x01);
      }
    }
    byte[][] output = Util.lenPrefixUnpack(buff.array(), numArrays);
    assertEquals(output.length, numArrays);
    for (int i = 0; i < output.length; i++) {
      assertEquals(output[i].length, arrayLength);
      for (byte b : output[i]) {
        assertEquals(b, 0x01);
      }
    }
  }
  
  public final void testBadLenPrefixUnpack() {
    byte[] bigOuterPrefixLength = ByteBuffer.allocate(4).putInt(1695609641).array();
    byte[] bigInnerPrefixLength = ByteBuffer.allocate(8).putInt(1).putInt(1695609641).array();
    byte[] negativeOuterPrefixLength = ByteBuffer.allocate(4).putInt(-1695609641).array();
    byte[] negativeInnerPrefixLength = ByteBuffer.allocate(8).putInt(1).putInt(-1).array();
    byte[] outOfBounds = ByteBuffer.allocate(12).putInt(1).putInt(5).putInt(1).array();
    byte[] goodByteArray = ByteBuffer.allocate(12).putInt(1).putInt(4).putInt(0).array();
    doTestBadLenPrefixUnpack(bigOuterPrefixLength, 2);
    doTestBadLenPrefixUnpack(bigInnerPrefixLength, 2);
    doTestBadLenPrefixUnpack(negativeOuterPrefixLength, 2);
    doTestBadLenPrefixUnpack(negativeInnerPrefixLength, 2);
    doTestBadLenPrefixUnpack(outOfBounds, 2);
    doTestBadLenPrefixUnpack(goodByteArray, 0);
  }
  
  public final void testLenPrefixUnpack() {
    for (int arrays = 0; arrays < 10; arrays++) {
      for (int arrayLength = 0; arrayLength < 100; arrayLength += 10) {
        doTestGoodLenPrefixUnpack(arrays, arrayLength);
      }
    }
  }

}
