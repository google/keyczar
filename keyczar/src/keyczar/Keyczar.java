package keyczar;

import java.io.InputStream;

import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;
import keyczar.internal.KeyMetadata;
import keyczar.internal.KeyVersion;

/**
 * Manages a Keyczar key set. Keys will not be read from a KeyczarReader until
 * the read() method is called.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public abstract class Keyczar {
  private final KeyczarReader reader;
  private KeyMetadata kmd;
  
  /**
   * Instantiates a new Keyczar object by passing it a Keyczar reader object 
   * 
   * @param reader A KeyczarReader to read keys from
   */
  public Keyczar(KeyczarReader reader) {
    this.reader = reader;
  }
  
  public void read() throws KeyczarException, DataPackingException {
    // Reads keys from the KeyczarReader
    InputStream metadata = reader.getMetadata();
    DataUnpacker unpacker = new DataUnpacker(metadata);
    kmd = KeyMetadata.getMetadata(unpacker);
    for (KeyVersion version : kmd.getVersions()) {
      reader.getKey(version.getVersionNumber());
    }
  }
}
