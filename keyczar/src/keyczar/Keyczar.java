// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

import keyczar.enums.KeyPurpose;
import keyczar.enums.KeyStatus;

/**
 * Manages a Keyczar key set. Keys will not be read from a KeyczarReader until
 * the read() method is called.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public abstract class Keyczar {
  private final HashMap<Integer, KeyczarKey> keyMap = new HashMap<Integer, KeyczarKey>();
  private final KeyMetadata kmd;
  private KeyVersion primaryVersion;
  private final HashMap<KeyVersion, KeyczarKey> versionMap = new HashMap<KeyVersion, KeyczarKey>();

  static final byte VERSION = 1;
  static final int KEY_HASH_SIZE = 4;
  static final int HEADER_SIZE = 1 + KEY_HASH_SIZE;

  /**
   * Instantiates a new Keyczar object by passing it a Keyczar reader object
   * 
   * @param reader A KeyczarReader to read keys from
   * @throws KeyczarException
   */
  public Keyczar(KeyczarReader reader) throws KeyczarException {
    // Reads keys from the KeyczarReader
    kmd = KeyMetadata.read(reader.getMetadata());
    if (!isAcceptablePurpose(kmd.getPurpose())) {
      throw new KeyczarException("Unacceptable purpose: " + kmd.getPurpose());
    }
    for (KeyVersion version : kmd.getVersions()) {
      if (version.getStatus() == KeyStatus.PRIMARY) {
        if (primaryVersion != null) {
          throw new KeyczarException(
              "Key sets may only have a single primary version");
        }
        primaryVersion = version;
      }
      KeyczarKey key = KeyczarKey.fromType(kmd.getType());
      key.read(reader.getKey(version.getVersionNumber()));
      if (keyMap.containsKey(key.hashCode())) {
        throw new KeyczarException("Key identifiers cannot collide");
      }
      keyMap.put(key.hashCode(), key);
      versionMap.put(version, key);
    }
  }

  /**
   * Instantiates a new Keyczar object with a KeyczarFileReader instantiated
   * with the given file location
   * 
   * @param fileLocation
   * @throws KeyczarException
   */
  public Keyczar(String fileLocation) throws KeyczarException {
    this(new KeyczarFileReader(fileLocation));
  }

  @Override
  public String toString() {
    return kmd.toString();
  }

  void addKey(KeyVersion version, KeyczarKey key) {
    keyMap.put(key.hashCode(), key);
    versionMap.put(version, key);
    kmd.addVersion(version);
  }

  // For KeyczarTool only
  void addVersion(KeyStatus status) throws KeyczarException {
    KeyVersion version = new KeyVersion(numVersions() + 1, status, false);
    if (status == KeyStatus.PRIMARY) {
      if (primaryVersion != null) {
        primaryVersion.setStatus(KeyStatus.ACTIVE);
      }
      primaryVersion = version;
    }
    KeyczarKey key = KeyczarKey.fromType(kmd.getType());
    do {
      // Make sure no keys collide on their identifiers
      key.generate();
    } while (getKey(key.hash()) != null);
    addKey(version, key);
  }

  KeyczarKey getKey(byte[] hash) {
    return keyMap.get(Util.toInt(hash));
  }

  KeyczarKey getKey(KeyVersion v) {
    return versionMap.get(v);
  }

  KeyMetadata getMetadata() {
    return kmd;
  }

  KeyczarKey getPrimaryKey() {
    if (primaryVersion == null) {
      return null;
    }
    return getKey(primaryVersion);
  }

  Iterator<KeyVersion> getVersions() {
    return Collections.unmodifiableSet(versionMap.keySet()).iterator();
  }

  abstract boolean isAcceptablePurpose(KeyPurpose purpose);

  int numVersions() {
    return versionMap.size();
  }
}
