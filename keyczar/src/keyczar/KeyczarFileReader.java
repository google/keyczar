package keyczar;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import keyczar.internal.KeyMetadata;

/**
 * Reads metadata and key files from the given location.
 * 
 * @author sweis@google.com (Your Name Here)
 *
 */
public class KeyczarFileReader implements KeyczarReader {
  private String location;
  private static final String META_FILE = "meta";
  
  public KeyczarFileReader(String fileLocation) {
    if (fileLocation != null && !fileLocation.endsWith(File.separator)) {
      fileLocation += File.separator;
    }
    this.location = fileLocation;
  }
  
  /* (non-Javadoc)
   * @see keyczar.KeyczarReader#getKey(int)
   */
  @Override
  public InputStream getKey(int version) throws KeyczarException {
    try {
      return new FileInputStream(new File(location + version));
    } catch (FileNotFoundException e) {
      throw new KeyczarException("Meta file not found in " + location, e);
    }
  }

  /* (non-Javadoc)
   * @see keyczar.KeyczarReader#getMetadata()
   */
  @Override
  public InputStream getMetadata() throws KeyczarException {
    try {
      return new FileInputStream(new File(location + META_FILE));
    } catch (FileNotFoundException e) {
      throw new KeyczarException("Meta file not found in " + location, e);
    }
    
  }
}
