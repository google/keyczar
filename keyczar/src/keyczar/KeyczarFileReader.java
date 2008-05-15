// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.io.Reader;


/**
 * Reads metadata and key files from the given location.
 * 
 * @author sweis@google.com (Your Name Here)
 *
 */
public class KeyczarFileReader extends KeyczarReader {
  private String location;
  static final String META_FILE = "meta";
  
  public KeyczarFileReader(String fileLocation) {
    if (fileLocation != null && !fileLocation.endsWith(File.separator)) {
      fileLocation += File.separator;
    }
    this.location = fileLocation;
  }
  
  @Override
  String getKey(int version) throws KeyczarException {
    return readFile(location + version);
  }

  @Override
  String getMetadata() throws KeyczarException {
    return readFile(location + META_FILE);
  }
  
  private String readFile(String filename) throws KeyczarException {
    try {
      RandomAccessFile file = new RandomAccessFile(filename, "r");
      byte[] contents = new byte[(int) file.length()];
      file.read(contents);
      file.close();
      return new String(contents);
    } catch (IOException e) {
      throw new KeyczarException("Error reading file " + filename, e);
    }
  }
}
