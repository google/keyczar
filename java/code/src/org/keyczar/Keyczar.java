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

package org.keyczar;

import org.apache.log4j.Logger;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.EncryptedReader;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Util;

import java.util.HashMap;

/**
 * Manages a Keyczar key set.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
abstract class Keyczar {
  static final Logger KEYCZAR_LOGGER = Logger.getLogger(Keyczar.class);
  static final byte FORMAT_VERSION = 0;
  static final byte[] FORMAT_BYTES = { FORMAT_VERSION };
  static final int KEY_HASH_SIZE = 4;
  static final int HEADER_SIZE = 1 + KEY_HASH_SIZE;

  final KeyMetadata kmd;
  KeyVersion primaryVersion;
  final HashMap<KeyVersion, KeyczarKey> versionMap =
    new HashMap<KeyVersion, KeyczarKey>();
  final HashMap<KeyHash, KeyczarKey> hashMap =
    new HashMap<KeyHash, KeyczarKey>(); // keep track of used hash identifiers

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
      return Util.toInt(data);
    }
  }

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
      KEYCZAR_LOGGER.info(Messages.getString("Keyczar.ReadVersion", version));
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

  KeyczarKey getPrimaryKey() {
    if (primaryVersion == null) {
      return null;
    }
    return versionMap.get(primaryVersion);
  }

  KeyczarKey getKey(byte[] hash) {
    return hashMap.get(new KeyHash(hash));
  }

  /**
   * Returns true if the purpose is acceptable for this key set.
   *
   * @param purpose
   * @return true if the purpose is acceptable, false otherwise.
   */
  abstract boolean isAcceptablePurpose(KeyPurpose purpose);
}