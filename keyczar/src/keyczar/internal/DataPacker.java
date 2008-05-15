package keyczar.internal;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Packs integers, longs, or byte arrays and writes them into output streams
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class DataPacker {
  private OutputStream output;
  private int tagCount;

  private static int MAX_VARINT_SIZE = 5;
  private static int MAX_VARLONG_SIZE = 10;

  /**
   * Instantiates a new DataPacker that will write data to the given output 
   * stream
   * 
   * @param output An output stream where the packed data will be written
   */
  public DataPacker(OutputStream output) {
    this.output = output;
    this.tagCount = 1;
  }

  /**
   * Packs the given array and writes it into the output stream
   * 
   * @param data The data to write
   * @return The number of bytes written
   * @throws DataPackingException If a write error occurs
   */
  public int putArray(byte[] data) throws DataPackingException {
    return putArray(data, 0, data.length);
  }

  /**
   * Packs len bytes from the given array from the offset and writes it into the
   * output stream 
   *
   * @param data The data to pack
   * @param offset The offset to start from
   * @param len The number of bytes to write
   * @return The number of bytes written
   * @throws DataPackingException If a write error occurs
   */
  public int putArray(byte[] data, int offset, int len) throws DataPackingException {
    int written = putByte(PackedDataType.ARRAY.getLabel(tagCount++));
    written += putIntNoTag(len);
    try {
      output.write(data, offset, len);
    } catch (IOException e) {
      throw new DataPackingException(e);
    }
    written += len;
    return written;
  }

  /**
   * Packs the given integer and writes it into the output stream
   * 
   * @param value The integer value to pack
   * @return The number of bytes written
   * @throws DataPackingException If a write error occurs
   */
  public int putInt(int value) throws DataPackingException {
    int written = putByte(PackedDataType.INT.getLabel(tagCount++));
    written+= putIntNoTag(value);
    return written;
  }
  
  /**
   * Packs the given long and writes it into the output stream
   * 
   * @param value The long value to pack
   * @return The number of bytes written
   * @throws DataPackingException If a write error occurs
   */
  public int putLong(long value) throws DataPackingException {
    int written = putByte(PackedDataType.LONG.getLabel(tagCount++));
    for (int i = 0; i < MAX_VARLONG_SIZE; i++) {
      byte b = (byte) (value & 0x7F);
      value >>>= 7;
      if (value == 0) {
        written += putByte(b);
        break;
      } else {
        // Set the continue bit to 1
        written += putByte((byte) (b | 0x80));
      }
    }
    return written;
  }
  
  private int putByte(byte b) throws DataPackingException {
    try {
      output.write(b);
      return 1;
    } catch (IOException e) {
      throw new DataPackingException(e);
    }
  }
  
  private int putIntNoTag(int value) throws DataPackingException {
    int written = 0;
    for (int i = 1; i <= MAX_VARINT_SIZE; i++) {
      byte b = (byte) (value & 0x7F);
      value >>>= 7;
      if (value == 0) {
        written += putByte(b);
        break;
      } else {
        // Set the continue bit to 1
        written += putByte((byte) (b | 0x80));
      }
    }
    return written;
  }

  /**
   * Returns how many bytes the given array would require when packed
   * 
   * @param data The input data
   * @return The number of bytes its packed form would require
   */
  static int arrayPackSize(byte[] data) {
    return intPackSize(data.length) + data.length;
  }

  /**
   * Returns how many bytes the given integer would require when packed
   * 
   * @param value The input value
   * @return The number of bytes its packed form would require
   */
  static int intPackSize(int value) {
    int len = 0;
    do {
      value >>>= 7;
      len++;
    } while (value != 0);
    return len;
  }

  /**
   * Returns how many bytes the given integer would require when packed
   * 
   * @param value The input value
   * @return The number of bytes its packed form would require
   */
  static int longPackSize(long value) {
    int len = 0;
    do {
      value >>>= 7;
      len++;
    } while (value != 0);
    return len;    
  }
}

