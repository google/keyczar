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

import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.EncryptedReader;
import com.google.keyczar.interfaces.KeyczarReader;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Reads metadata and encrypted key files from the given reader.
 * 
 * @author sweis@google.com (Steve Weis)
 * 
 */
class KeyczarEncryptedReader implements EncryptedReader {
  private KeyczarReader reader;
  private Crypter crypter;

  /**
   * Reads encrypted key files from the given reader and decrypts them
   * with the given crypter.
   * 
   * @param reader The reader to read files from.
   * @param crypter The crypter to decrypt keys with. 
   */
  KeyczarEncryptedReader(KeyczarReader reader, Crypter crypter) {
    this.reader = reader;
    this.crypter = crypter;
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    return crypter.decrypt(reader.getKey(version));
  }

  @Override
  public String getMetadata() throws KeyczarException {
    return reader.getMetadata();
  }
}
