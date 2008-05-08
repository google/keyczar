// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;
import keyczar.internal.Util;

/**
 * Manages a Keyczar key set. Keys will not be read from a KeyczarReader until
 * the read() method is called.
 *
 * This class is not thread-safe.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
class Keyczar {
  private final KeyczarReader reader;
  private KeyMetadata kmd;
  private KeyVersion primaryVersion;
  private ArrayList<KeyczarKey> keys = new ArrayList<KeyczarKey>();  
  private HashMap<Integer, KeyczarKey> keyMap =
    new HashMap<Integer, KeyczarKey>();

  /**
   * Instantiates a new Keyczar object with a KeyczarFileReader instantiated
   * with the given file location 
   * 
   * @param fileLocation 
   */
  public Keyczar(String fileLocation) {
    this(new KeyczarFileReader(fileLocation));
  }
  
  /**
   * Instantiates a new Keyczar object by passing it a Keyczar reader object 
   * 
   * @param reader A KeyczarReader to read keys from
   */
  public Keyczar(KeyczarReader reader) {
    this.reader = reader;
  }
    
  public void read() throws KeyczarException {
    // Reads keys from the KeyczarReader
    InputStream metaData = reader.getMetadata();
    DataUnpacker metaDataUnpacker = new DataUnpacker(metaData);
    kmd = KeyMetadata.getMetadata(metaDataUnpacker);
    if (!isAcceptablePurpose(kmd.getPurpose())) {
      throw new KeyczarException("Unacceptable purpose: "
          + kmd.getPurpose());
    }
    for (KeyVersion version : kmd.getVersions()) {
      if (version.getStatus() == KeyStatus.PRIMARY) {
        if (primaryVersion != null) {
          throw new KeyczarException(
              "Key sets may only have a single primary version");
        }
        primaryVersion = version;
      }
      InputStream keyData = reader.getKey(version.getVersionNumber());
      DataUnpacker keyDataUnpacker = new DataUnpacker(keyData);
      KeyczarKey key = KeyczarKey.fromType(kmd.getType());
      key.read(keyDataUnpacker);
      keys.add(key);
      keyMap.put(Util.toInt(key.hash()), key);
    }
  }

  KeyczarKey getKey(byte[] hash) {
    return keyMap.get(Util.toInt(hash));
  }
  
  KeyczarKey getKey(KeyVersion v) {
    return keys.get(v.getVersionNumber() - 1);
  }
  
  KeyczarKey getPrimaryKey() {
    if (primaryVersion == null)
      return null;

    return keys.get(primaryVersion.getVersionNumber() - 1);
  }
  
  KeyVersion getVersion(int i) {
    return kmd.getVersions().get(i);
  }

  int numVersions() {
    return kmd.getVersions().size();
  }
  
  KeyMetadata getMetadata() {
    return kmd;
  }

  protected boolean isAcceptablePurpose(KeyPurpose purpose) {
    return true;
  }

  // For KeyczarTool only
  void setMetadata(KeyMetadata kmd) {
    this.kmd = kmd;
  }
  
  // For KeyczarTool and constructor only
  void addVersion(KeyStatus status)
      throws KeyczarException {
    KeyVersion version = new KeyVersion(numVersions() + 1, status, false);
    if (status == KeyStatus.PRIMARY) {
      if (primaryVersion != null) {
        primaryVersion.setStatus(KeyStatus.ACTIVE);
      }
      primaryVersion = version;
    }
    kmd.getVersions().add(version);
    KeyczarKey key = KeyczarKey.fromType(kmd.getType());
    key.generate();
    keys.add(key);
  }
}