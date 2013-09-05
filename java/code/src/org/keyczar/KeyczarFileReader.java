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
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Reads metadata and key files from the given location.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class KeyczarFileReader implements KeyczarReader {
  private String location;
  static final String META_FILE = "meta";

  public KeyczarFileReader(String fileLocation) {
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
  public String getKey() throws KeyczarException {
    KeyMetadata metadata = KeyMetadata.read(getMetadata());
	
    return getKey(metadata.getPrimaryVersion().getVersionNumber());
  }

  @Override
  public String getMetadata() throws KeyczarException {
    return readFile(location + META_FILE);
  }

  private String readFile(String filename) throws KeyczarException {
    try {
      File file = new File(filename);
      FileInputStream fis = new FileInputStream(file);
      try {
        byte[] contents = Util.readStreamFully(fis);
        return new String(contents);
      } finally {
        fis.close();
      }
    } catch (IOException e) {
      throw new KeyczarException(
          Messages.getString("KeyczarFileReader.FileError", filename), e);
    }
  }
}