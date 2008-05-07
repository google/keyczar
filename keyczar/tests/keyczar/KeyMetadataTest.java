package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import keyczar.KeyMetadata;
import keyczar.KeyPurpose;
import keyczar.KeyStatus;
import keyczar.KeyType;
import keyczar.KeyVersion;
import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;

public class KeyMetadataTest {
  ByteArrayOutputStream output;
  KeyVersion v = new KeyVersion(3, KeyStatus.ACTIVE, false);
  KeyVersion v2 = new KeyVersion(5, KeyStatus.PRIMARY, true);

  
  @Before
  public void setUp() throws Exception {
    output = new ByteArrayOutputStream();
  }
  
  @Test
  public final void testWriteAndReadNoVersions() throws DataPackingException {
    KeyMetadata kmd = new KeyMetadata("Testing", KeyPurpose.DECRYPT_AND_ENCRYPT,
        KeyType.AES);
    DataPacker packer = new DataPacker(output);
    int written = kmd.write(packer);
    byte[] outputBytes = output.toByteArray();
    assertEquals(written, outputBytes.length);
    
    // Check that we can read back in the packed data
    ByteArrayInputStream input = new ByteArrayInputStream(outputBytes);
    DataUnpacker unpacker = new DataUnpacker(input);
    KeyMetadata kmdRead = KeyMetadata.getMetadata(unpacker);
    assertEquals("Testing", kmdRead.getName());
    assertEquals(KeyPurpose.DECRYPT_AND_ENCRYPT, kmdRead.getPurpose());
    assertEquals(KeyType.AES, kmdRead.getType());
  }
  
  @Test
  public final void testReadMetadataNoVersions() throws DataPackingException {
    byte[] packedData = 
        {10, 7, 84, 101, 115, 116, 105, 110, 103, 16, 0, 24, 0, 32, 0};
    ByteArrayInputStream input = new ByteArrayInputStream(packedData);
    DataUnpacker unpacker = new DataUnpacker(input);
    
    KeyMetadata kmdRead = KeyMetadata.getMetadata(unpacker);
    assertEquals("Testing", kmdRead.getName());
    assertEquals(KeyPurpose.DECRYPT_AND_ENCRYPT, kmdRead.getPurpose());
    assertEquals(KeyType.AES, kmdRead.getType());
  }
  
  @Test
  public final void testWriteAndRead() throws DataPackingException {
    KeyMetadata kmd = new KeyMetadata("Testing2", KeyPurpose.SIGN_AND_VERIFY,
        KeyType.HMAC_SHA1); 
    kmd.addVersion(v);
    kmd.addVersion(v2);
    
    DataPacker packer = new DataPacker(output);
    int written = kmd.write(packer);
    byte[] outputBytes = output.toByteArray();
    assertEquals(written, outputBytes.length);
    
    // Check that we can read back in the packed data
    ByteArrayInputStream input = new ByteArrayInputStream(outputBytes);
    DataUnpacker unpacker = new DataUnpacker(input);
    KeyMetadata kmdRead = KeyMetadata.getMetadata(unpacker);
    assertEquals("Testing2", kmdRead.getName());
    assertEquals(KeyPurpose.SIGN_AND_VERIFY, kmdRead.getPurpose());
    assertEquals(KeyType.HMAC_SHA1, kmdRead.getType());
    
    KeyVersion readV = kmdRead.getVersion(0);
    assertTrue(v.equals(readV));
    KeyVersion readV2 = kmdRead.getVersion(1);
    assertTrue(v2.equals(readV2));
  }
  
  @Test
  public final void testRead() throws DataPackingException {
    byte[] packedBytes = {10, 8, 84, 101, 115, 116, 105, 110, 103, 50,
        16, 2, 24, 1, 32, 2, 40, 3, 48, 1, 56, 0, 64, 5, 72, 0, 80, 1};
    // Check that we can read back in the packed data
    ByteArrayInputStream input = new ByteArrayInputStream(packedBytes);
    DataUnpacker unpacker = new DataUnpacker(input);
    KeyMetadata kmdRead = KeyMetadata.getMetadata(unpacker);
    assertEquals("Testing2", kmdRead.getName());
    assertEquals(KeyPurpose.SIGN_AND_VERIFY, kmdRead.getPurpose());
    assertEquals(KeyType.HMAC_SHA1, kmdRead.getType());
    
    KeyVersion readV = kmdRead.getVersion(0);
    assertTrue(v.equals(readV));
    KeyVersion readV2 = kmdRead.getVersion(1);
    assertTrue(v2.equals(readV2));
  }
}
