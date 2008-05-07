// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;

/**
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
class KeyczarFileWriter {
  private KeyczarFileWriter() {
    
  }
  static void writeKeyczar(String location, Keyczar keyczar)
      throws KeyczarException {
    if (location != null && !location.endsWith(File.separator)) {
      location += File.separator;
    }
    writeMetadata(location, keyczar.getMetadata());
    for (int i = 0; i < keyczar.numVersions(); i++) {
      KeyVersion version = keyczar.getVersion(i);
      writeVersion(location, version, keyczar.getKey(version));
    }
  }
  
  private static void writeMetadata(String location, KeyMetadata kmd)
      throws KeyczarException {
    File file = new File(location + KeyczarFileReader.META_FILE);
    FileOutputStream metaOutput;
    try {
      metaOutput = new FileOutputStream(file);
      DataPacker packer = new DataPacker(metaOutput);
      kmd.write(packer);
      metaOutput.close();
    } catch (IOException e) {
      throw new KeyczarException("Unable to write to : " + file.toString(), e);
    }
  }
  
  private static void writeVersion(String location, KeyVersion version,
      KeyczarKey key) throws KeyczarException {
    File file = new File(location + version.getVersionNumber());
    FileOutputStream keyOutput;
    try {
      keyOutput = new FileOutputStream(file);
      DataPacker packer = new DataPacker(keyOutput);
      key.write(packer);
      keyOutput.close();
    } catch (IOException e) {
      throw new KeyczarException("Unable to write to : " + file.toString(), e);
    }
  }
}
