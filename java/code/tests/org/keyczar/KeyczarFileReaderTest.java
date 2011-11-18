/*
 * Copyright 2011 Google Inc.
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

import junit.framework.TestCase;

import org.keyczar.exceptions.NoPrimaryKeyException;
import org.keyczar.interfaces.KeyczarReader;

/**
 * Test for primary key loading for KeyczarReader.
 * 
 * @author normandl@google.com (David Norman)
 */

public class KeyczarFileReaderTest extends TestCase {
  private static final String TEST_DATA = "./testdata";

  public void testGetPrimary() throws Exception {
	// based on the checked in files, we know version 2 is primary.
	KeyczarReader reader = new KeyczarFileReader(TEST_DATA + "/rsa");
	String knownPrimaryKey = reader.getKey(2 /* primary key version */);
	String readerKey = reader.getKey();
	
	assertEquals(knownPrimaryKey, readerKey);
  }
  
  public void testGetPrimaryFails() throws Exception {
    KeyczarReader reader = new KeyczarFileReader(TEST_DATA + "/aes-noprimary");

    try {
      reader.getKey();
      fail("should not read a primary key");
    } catch (NoPrimaryKeyException e) {
    	// expected
    }
  }
}
