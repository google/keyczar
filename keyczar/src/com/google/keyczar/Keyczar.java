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
import com.google.keyczar.interfaces.KeyczarReader;

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
      // TODO: Check -- changed (data[2] & 0xFF) << 24 to ... << 8. OK?
      // Also is & 0xFF necessary? doesn't seem to change the value at all?
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
      KeyczarKey key = KeyczarKey.readKey(kmd.getType(),
          reader.getKey(version.getVersionNumber()));
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

  void addKey(KeyVersion version, KeyczarKey key) {
    hashMap.put(new KeyHash(key.hash()), key);
    versionMap.put(version, key);
    kmd.addVersion(version);
  }

  /**
   * Adds a new key version with given status and next available version 
   * number to key set. Generates a new key of same type (repeated until hash
   * identifier is unique) for this version.
   * 
   * @param status KeyStatus desired for new key version
   * @throws KeyczarException if key type is unsupported.
   */
  // For KeyczarTool only
  // TODO: if only for KeyCzarTool, maybe move to GenericKeyczar?
  void addVersion(KeyStatus status) throws KeyczarException {
    KeyVersion version = new KeyVersion(numVersions() + 1, status, false);
    if (status == KeyStatus.PRIMARY) {
      if (primaryVersion != null) {
        primaryVersion.setStatus(KeyStatus.ACTIVE);
      }
      primaryVersion = version;
    }
    KeyczarKey key;
    do { // Make sure no keys collide on their identifiers
      key = KeyczarKey.genKey(kmd.getType());
    } while (getKey(key.hash()) != null);
    addKey(version, key);
  }
  
  /**
   * Promotes the status of key with given version number. Promoting ACTIVE key
   * automatically demotes current PRIMARY key to ACTIVE.
   * 
   * @param versionNumber integer version number to promote
   * @throws KeyczarException if invalid version number or trying to promote
   * a primary key.
   */
  //TODO: also used in KeyczarTool, does it belong in GenericKeyczar?
  void promote(int versionNumber) throws KeyczarException {
    KeyVersion version = kmd.getVersion(versionNumber);
    if (version == null) {
      throw new KeyczarException("No such version number: " + versionNumber);
    }
    switch (version.getStatus()) {
      case PRIMARY:
        throw new KeyczarException("Can't promote a primary key.");
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
  //TODO: also used in KeyczarTool, does it belong in GenericKeyczar?
  void demote(int versionNumber) throws KeyczarException {
    KeyVersion version = kmd.getVersion(versionNumber);
    if (version == null) {
      throw new KeyczarException("No such version number: " + versionNumber);
    }
    switch (version.getStatus()) {
      case PRIMARY:
        version.setStatus(KeyStatus.ACTIVE);
        primaryVersion = null; // no more PRIMARY keys in the set
        break;
      case ACTIVE: 
        version.setStatus(KeyStatus.SCHEDULED_FOR_REVOCATION);
        break;
      case SCHEDULED_FOR_REVOCATION:
        throw new KeyczarException("Can't demote a key scheduled " + 
            "for revocation.");
    }
  }
  
  /**
   * Updates the status of key with given version number to the given status.
   * Can't change directly from PRIMARY to SCHEDULED_FOR_REVOCATION and 
   * vice versa.
   * 
   * @param versionNumber integer version number to update
   * @param status new desired KeyStatus
   * @throws KeyczarException if status or versionNumber are invalid or if
   * requested status change is illegal.
   */
  @Deprecated
  //TODO: promote and demote used now, but keep around for testing purposes?
  void setStatus(int versionNumber, KeyStatus status) throws KeyczarException {
    if (status == null) {
      throw new KeyczarException("Invalid status.");
    }
    KeyVersion version = kmd.getVersion(versionNumber);
    if (version == null) {
      throw new KeyczarException("No such version number: " + versionNumber);
    }
    KeyStatus oldStatus = version.getStatus();
    switch(oldStatus) { // All transitions legal for ACTIVE key
      case PRIMARY:
        if (status == KeyStatus.SCHEDULED_FOR_REVOCATION) {
          throw new KeyczarException("Illegal status change - can't change" + 
              "primary key directly to be scheduled for revocation.");
        }
        break;
      case SCHEDULED_FOR_REVOCATION:
        if (status == KeyStatus.PRIMARY) {
          throw new KeyczarException("Illegal status change - can't change" + 
              "a key scheduled for revocation directly to primary key.");
        }
        break;
    }
    version.setStatus(status); // legal status change, including no change
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

  //TODO: changed from returning Iterator to Set and using for-each construct
  // in rest of code instead - OK? any reason to keep Iterator?
  Set<KeyVersion> getVersions() {
    return Collections.unmodifiableSet(versionMap.keySet());
  }

  abstract boolean isAcceptablePurpose(KeyPurpose purpose);

  int numVersions() {
    return versionMap.size();
  }
}
