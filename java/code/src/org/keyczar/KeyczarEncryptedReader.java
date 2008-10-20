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

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.EncryptedReader;
import org.keyczar.interfaces.KeyczarReader;

/**
 * Reads metadata and encrypted key files from the given reader.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class KeyczarEncryptedReader implements EncryptedReader {
  private KeyczarReader reader;
  private Crypter crypter;

  /**
   * Reads encrypted key files from the given reader and decrypts them
   * with the given crypter.
   *
   * @param reader The reader to read files from.
   * @param crypter The crypter to decrypt keys with.
   */
  public KeyczarEncryptedReader(KeyczarReader reader, Crypter crypter) {
    this.reader = reader;
    this.crypter = crypter;
  }

  public String getKey(int version) throws KeyczarException {
    return crypter.decrypt(reader.getKey(version));
  }

  public String getMetadata() throws KeyczarException {
    return reader.getMetadata();
  }
}