package keyczar;

import java.io.InputStream;

/**
 * An interface for KeyczarReaders. Typically, these will read key files from 
 * disk, but may be implemented to read from arbitrary sources.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
interface KeyczarReader {
  /**
   * Returns an input stream of a particular version of a packed key  
   * 
   * @param version The Version number of the key to read
   * @return A packed data representation of a Key 
   * @throws KeyczarException If an error occurs while attempting to read data,
   *                          e.g. an IOException
   */
  InputStream getKey(int version) throws KeyczarException;
  
  /**
   * @return A packed data representation of KeyMetadata
   * @throws KeyczarException If an error occurs while attempting to read data,
   *                          e.g. an IOException
   */
  InputStream getMetadata() throws KeyczarException;
}