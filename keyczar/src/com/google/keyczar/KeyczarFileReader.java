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
import com.google.keyczar.interfaces.KeyczarReader;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;



/**
 * Reads metadata and key files from the given location.
 * 
 * @author sweis@google.com (Your Name Here)
 * 
 */
class KeyczarFileReader implements KeyczarReader {
  private String location;
  static final String META_FILE = "meta";

  KeyczarFileReader(String fileLocation) {
    if (fileLocation != null && !fileLocation.endsWith(File.separator)) {
      fileLocation += File.separator;
    }
    location = fileLocation;
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    return readFile(location + version);
  }

  @Override
  public String getMetadata() throws KeyczarException {
    return readFile(location + META_FILE);
  }

  private String readFile(String filename) throws KeyczarException {
    try {
      RandomAccessFile file = new RandomAccessFile(filename, "r");
      byte[] contents = new byte[(int) file.length()];
      file.read(contents);
      file.close();
      return new String(contents);
    } catch (IOException e) {
      throw new KeyczarException("Error reading file " + filename, e);
    }
  }
}
