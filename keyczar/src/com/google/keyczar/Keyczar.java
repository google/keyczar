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
import com.google.keyczar.util.Util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Manages a Keyczar key set. Keys will not be read from a KeyczarReader until
 * the read() method is called.
 * 
 * @author steveweis@gmail.com (Steve Weis)
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
        (data[2] & 0xFF) << 24  | (data[3] & 0xFF);
    }
  }
  
  private final KeyMetadata kmd;
  private KeyVersion primaryVersion;
  private final HashMap<KeyVersion, KeyczarKey> versionMap =
    new HashMap<KeyVersion, KeyczarKey>();
  private final HashMap<KeyHash, KeyczarKey> hashMap =
    new HashMap<KeyHash, KeyczarKey>();
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

  // For KeyczarTool only
  void addVersion(KeyStatus status) throws KeyczarException {
    KeyVersion version = new KeyVersion(numVersions() + 1, status, false);
    if (status == KeyStatus.PRIMARY) {
      if (primaryVersion != null) {
        primaryVersion.setStatus(KeyStatus.ACTIVE);
      }
      primaryVersion = version;
    }
    KeyczarKey key;
    do {
      // Make sure no keys collide on their identifiers
      key = KeyczarKey.genKey(kmd.getType());
    } while (getKey(key.hash()) != null);
    addKey(version, key);
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

  Iterator<KeyVersion> getVersions() {
    return Collections.unmodifiableSet(versionMap.keySet()).iterator();
  }

  abstract boolean isAcceptablePurpose(KeyPurpose purpose);

  int numVersions() {
    return versionMap.size();
  }
}
