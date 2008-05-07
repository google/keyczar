package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import keyczar.KeyStatus;
import keyczar.KeyVersion;
import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;

public class KeyVersionTest {
  static KeyVersion v = new KeyVersion(3, KeyStatus.ACTIVE, false);
  static KeyVersion v2 = new KeyVersion(5, KeyStatus.PRIMARY, true);
  @Test
  public final void testWriteAndRead() throws DataPackingException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataPacker packer = new DataPacker(output);
    int written = v.write(packer);
    byte[] outputBytes = output.toByteArray();
    assertEquals(written, outputBytes.length);
    
    // Test that the data we read is correct
    ByteArrayInputStream input = new ByteArrayInputStream(outputBytes);
    DataUnpacker unpacker = new DataUnpacker(input);
    KeyVersion readV = KeyVersion.getVersion(unpacker);
    assertTrue(v.equals(readV));
    
    written += v2.write(packer);
    outputBytes = output.toByteArray();
    assertEquals(written, outputBytes.length);
    
    // Try reading two successive versions
    input = new ByteArrayInputStream(outputBytes);
    unpacker = new DataUnpacker(input);
    
    readV = KeyVersion.getVersion(unpacker);
    assertTrue(v.equals(readV));

    KeyVersion readV2 = KeyVersion.getVersion(unpacker);
    assertTrue(v2.equals(readV2));
  }


  @Test
  public final void testRead() throws DataPackingException {
    byte[] packedData = {8, 3, 16, 1, 24, 0, 32, 5, 40, 0, 48, 1};
    ByteArrayInputStream input = new ByteArrayInputStream(packedData);
    DataUnpacker unpacker = new DataUnpacker(input);
    
    KeyVersion readV = KeyVersion.getVersion(unpacker);
    assertTrue(v.equals(readV));
    
    KeyVersion readV2 = KeyVersion.getVersion(unpacker);
    assertTrue(v2.equals(readV2));
  }
}
