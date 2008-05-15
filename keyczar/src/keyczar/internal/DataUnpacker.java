package keyczar.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads packed integers, longs, and byte arrays from an input stream and
 * unpacks them.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class DataUnpacker {
  private int tagCount;
  private static InputStream input;
  
  private static int MAX_VARINT_SIZE = 5;
  private static int MAX_VARLONG_SIZE = 10;
  
  /**
   * Instantiates a new DataUnpacker that will read data from the given input
   * stream
   * 
   * @param input An input stream containing packed data
   */
  public DataUnpacker(InputStream input) {
    DataUnpacker.input = input;
    this.tagCount = 1;
  }
  
  public DataUnpacker(byte[] input) {
    this(input, 0, input.length);
  }

  public DataUnpacker(byte[] input, int offset, int length) {
    this(new ByteArrayInputStream(input, offset, length)); 
  }
  
  public PackedDataType peek() throws DataPackingException {
    if (input.markSupported()) {
      input.mark(1);
      byte value = getByte();
      try {
        input.reset();
      } catch (IOException e) {
        throw new DataPackingException(e);
      }
      return PackedDataType.fromByte(value);
    } else {
      throw new DataPackingException("Unsupported");
    }
  }

  /**
   * Destructively tries to unpack an array from the input stream. If an
   * exception is thrown, the stream should be considered corrupted.
   * 
   * @return An unpacked byte array  
   * @throws DataPackingException If a read error occurs,
   *                              or if the stream is corrupted
   */
  public byte[] getArray() throws DataPackingException {
    checkTagFormat(PackedDataType.ARRAY);
    int len = getIntNoTag();
    // Now position is pointing at the start of the array data
    byte[] output = new byte[len];
    try {
      input.read(output, 0, len);
    } catch (IOException e) {
      throw new DataPackingException(e);
    }
    return output;
  }

  /**
   * Destructively tries to unpack an array from the input stream into a
   * destination array. If an exception is thrown, the stream should be
   * considered corrupted.
   * 
   * @param dest The destination array to write the unpacked data in
   * @param offset The offset to start writing from
   * @throws DataPackingException If a read error occurs,
   *                              or if the stream is corrupted
   */
  void getArray(byte[] dest, int offset) throws DataPackingException {
    checkTagFormat(PackedDataType.ARRAY);
    int len = getIntNoTag();
    try {
      input.read(dest, offset, len);
    } catch (IOException e) {
      throw new DataPackingException(e);
    }
  }
  
  /**
   * Destructively tries to unpack an integer from the input stream.  If an
   * exception is thrown, the stream should be considered corrupted.
   *  
   * @return An unpacked integer
   * @throws DataPackingException If a read error occurs,
   *                              or if the stream is corrupted
   */
  public int getInt() throws DataPackingException {
    checkTagFormat(PackedDataType.INT);
    return getIntNoTag();
  }
  
  /**
   * Destructively tries to unpack a long from the input stream.  If an
   * exception is thrown, the stream should be considered corrupted.
   * 
   * @return An unpacked long
   * @throws DataPackingException If a read error occurs,
   *                              or if the stream is corrupted
   */
  long getLong() throws DataPackingException {
    checkTagFormat(PackedDataType.LONG);
    long result = 0;
    for (int i = 0; i < MAX_VARLONG_SIZE; i++) {
      byte tmp = getByte();
      result |= ((long) (tmp & 0x7F)) << (7 * i);
      if (tmp >= 0) {
        break;
      }
    }
    return result;
  }
    
  private void checkTagFormat(PackedDataType format)
      throws DataPackingException {
    int tag;
    try {
      tag = input.read();
    } catch (IOException e) {
      throw new DataPackingException(e);
    }
    if ((tag >>> 3) != tagCount) {
      throw new DataPackingException("Invalid packed data tag. " +
          "Expected count: " + tagCount);
    }
    if ((tag & 0x07) != format.getValue()) {
      throw new DataPackingException("Expected format: " + format +
          ", Received: " + (tag & 0x07));
    }
    
    // Increment the tag count if all went well.
    tagCount++;
  }
  
  private byte getByte() throws DataPackingException {
    try {
      return (byte) input.read();
    } catch (IOException e) {
      throw new DataPackingException(e);
    }
  }

  private int getIntNoTag() throws DataPackingException {
    int result = 0;
    for (int i = 0; i < MAX_VARINT_SIZE; i++) {
      byte tmp = getByte();
      result |= (tmp & 0x7F) << (7 * i);
      if (tmp >= 0) {
        break;
      }
    }
    return result;
  }
}

