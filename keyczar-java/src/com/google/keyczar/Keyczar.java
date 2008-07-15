/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.keyczar;

import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.enums.KeyStatus;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.i18n.Messages;
import com.google.keyczar.interfaces.EncryptedReader;
import com.google.keyczar.interfaces.KeyczarReader;

import org.apache.log4j.Logger;

import java.util.Collections;
import java.util.HashMap;
import java.util.Set;

/**
 * Manages a Keyczar key set. Keys will not be read from a KeyczarReader until
 * the read() method is called.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 * 
 */
abstract class Keyczar {
  private static final Logger logger = Logger.getLogger(Keyczar.class);

  private class KeyHash {
    private byte[] data;
    
    private KeyHash(byte[] d) {
      if (d.length != KEY_HASH_SIZE) {
        throw new IllegalArgumentException();
      }
      data = d;
    }
    
    @Override
    public boolean equals(Object o) {
      return (o instanceof KeyHash && o.hashCode() == this.hashCode());
    }
    
    @Override
    public int hashCode() {
      return (data[0] & 0xFF) << 24 | (data[1] & 0xFF) << 16 | 
        (data[2] & 0xFF) << 8  | (data[3] & 0xFF);
      // CHECK: is & 0xFF necessary? doesn't seem to change the value at all?
      // But removing & 0xFF them seems to break last test in CrypterTest, why?
    }
  }
  
  private final KeyMetadata kmd;
  private KeyVersion primaryVersion;
  private final HashMap<KeyVersion, KeyczarKey> versionMap =
    new HashMap<KeyVersion, KeyczarKey>();
  private final HashMap<KeyHash, KeyczarKey> hashMap =
    new HashMap<KeyHash, KeyczarKey>(); // keep track of used hash identifiers
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
      throw new KeyczarException(
          Messages.getString("Keyczar.UnacceptablePurpose", kmd.getPurpose()));
    }
    
    if (kmd.isEncrypted() && !(reader instanceof EncryptedReader)) {
      throw new KeyczarException(
          Messages.getString("Keyczar.NeedEncryptedReader"));
    }
    for (KeyVersion version : kmd.getVersions()) {
      if (version.getStatus() == KeyStatus.PRIMARY) {
        if (primaryVersion != null) {
          throw new KeyczarException(
              Messages.getString("Keyczar.SinglePrimary"));
        }
        primaryVersion = version;
      }
      KeyczarKey key = KeyczarKey.readKey(kmd.getType(),
          reader.getKey(version.getVersionNumber()));
      logger.info(Messages.getString("Keyczar.ReadVersion", version));
      hashMap.put(new KeyHash(key.hash()), key);
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

  /**
   * Adds a new KeyczarKey (new version) to the key store. Associates it
   * with given version. Adds new KeyVersion to the key set.
   * 
   * @param version KeyVersion
   * @param key KeyczarKey
   */
  void addKey(KeyVersion version, KeyczarKey key) {
    hashMap.put(new KeyHash(key.hash()), key);
    versionMap.put(version, key);
    kmd.addVersion(version);
  }

  // Commands For KeyczarTool only
  // TODO(arkajit.dey): if only for KeyCzarTool, maybe move to GenericKeyczar?
  // sweis: Then we need to make kmd package readable. I prefer having it
  // private. Plus, we may want to dynamically add new key versions in the
  // future.
  /**
   * Uses default key size to add a new key version.
   * 
   * @param status KeyStatus desired for new key version
   */
  void addVersion(KeyStatus status) throws KeyczarException {
    addVersion(status, kmd.getType().defaultSize());
  }
  
  /**
   * Adds a new key version with given status and next available version 
   * number to key set. Generates a new key of same type (repeated until hash
   * identifier is unique) for this version. Uses supplied key size in lieu
   * of the default key size. If this is an unacceptable key size, defaults
   * to the default key size.
   * 
   * @param status KeyStatus desired for new key version
   * @param keySize desired key size in bits
   * @throws KeyczarException if key type is unsupported.
   */
  void addVersion(KeyStatus status, int keySize) throws KeyczarException {
    KeyVersion version = new KeyVersion(numVersions() + 1, status, false);
    if (status == KeyStatus.PRIMARY) {
      if (primaryVersion != null) {
        primaryVersion.setStatus(KeyStatus.ACTIVE);
      }
      primaryVersion = version;
    }
    KeyczarKey key;
    kmd.getType().setKeySize(keySize);
    if (keySize < kmd.getType().defaultSize()) { // print a warning statement
      logger.warn(Messages.getString("Keyczar.SizeWarning",
          keySize, kmd.getType().defaultSize(), kmd.getType().toString()));
    }
    do { // Make sure no keys collide on their identifiers
      key = KeyczarKey.genKey(kmd.getType());
    } while (getKey(key.hash()) != null);
    kmd.getType().resetDefaultKeySize(); //TODO: bit clunky, any workaround
    // avoiding programmer having to reset default size each time?
    // maybe automatically reset after any calls to KeyType.keySize()?
    // this would only allow one time changes to keySize
    addKey(version, key);
    logger.info(Messages.getString("Keyczar.NewVersion", version));
  }
  
  /**
   * Promotes the status of key with given version number. Promoting ACTIVE key
   * automatically demotes current PRIMARY key to ACTIVE.
   * 
   * @param versionNumber integer version number to promote
   * @throws KeyczarException if invalid version number or trying to promote
   * a primary key.
   */
  void promote(int versionNumber) throws KeyczarException {
    KeyVersion version = getVersion(versionNumber);
    logger.info(Messages.getString("Keyczar.PromotedVersion", version));
    switch (version.getStatus()) {
      case PRIMARY:
        throw new KeyczarException(
            Messages.getString("Keyczar.CantPromotePrimary"));
      case ACTIVE: 
        version.setStatus(KeyStatus.PRIMARY); // promote to PRIMARY
        if (primaryVersion != null) {
          primaryVersion.setStatus(KeyStatus.ACTIVE); // only one PRIMARY key
        }
        primaryVersion = version;
        break;
      case SCHEDULED_FOR_REVOCATION:
        version.setStatus(KeyStatus.ACTIVE);
        break;
    }
  }
  
  /**
   * Demotes the status of key with given version number. Demoting PRIMARY key
   * results in a key set with no primary version.
   * 
   * @param versionNumber integer version number to demote
   * @throws KeyczarException if invalid version number or trying to demote
   * a key scheduled for revocation.
   */
  void demote(int versionNumber) throws KeyczarException {
    KeyVersion version = getVersion(versionNumber);
    logger.info(Messages.getString("Keyczar.DemotingVersion", version));
    switch (version.getStatus()) {
      case PRIMARY:
        version.setStatus(KeyStatus.ACTIVE);
        primaryVersion = null; // no more PRIMARY keys in the set
        break;
      case ACTIVE: 
        version.setStatus(KeyStatus.SCHEDULED_FOR_REVOCATION);
        break;
      case SCHEDULED_FOR_REVOCATION:
        throw new KeyczarException(
            Messages.getString("Keyczar.CantDemoteScheduled"));
    }
  }
  
  /**
   * Revokes the key with given version number if it is scheduled to be revoked.
   * 
   * @param versionNumber integer version number to be revoked
   * @throws KeyczarException if version number nonexistent or key is not
   * scheduled for revocation.
   */
  void revoke(int versionNumber) throws KeyczarException {
    KeyVersion version = getVersion(versionNumber);
    if (version.getStatus() == KeyStatus.SCHEDULED_FOR_REVOCATION) {
      kmd.removeVersion(versionNumber);
    } else {
      throw new KeyczarException(Messages.getString("Keyczar.CantRevoke"));
    }
  }

  /**
   * Returns the version corresponding to the version number if it exists.
   * 
   * @param versionNumber
   * @return KeyVersion if it exists
   * @throws KeyczarException if version number doesn't exist
   */
   KeyVersion getVersion(int versionNumber) throws KeyczarException {
    KeyVersion version = kmd.getVersion(versionNumber);
    if (version == null) {
      throw new KeyczarException(
          Messages.getString("Keyczar.NoSuchVersion", versionNumber));
    }
    return version;
  }
  
  KeyczarKey getKey(byte[] hash) {
    return hashMap.get(new KeyHash(hash));
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

  Set<KeyVersion> getVersions() {
    return Collections.unmodifiableSet(versionMap.keySet());
  }

  abstract boolean isAcceptablePurpose(KeyPurpose purpose);

  int numVersions() {
    return versionMap.size();
  }
}
