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

package com.google.security.keyczar;

import com.google.keyczar.MockKeyczarReader;
import com.google.keyczar.interfaces.KeyczarReader;

import junit.framework.TestCase;

import org.junit.Test;

/**
 * TODO: automate KeyczarTool testing
 * 
 * Rough Strategy: mock out KeyczarReader, use to influence creation of a
 * GenericKeyCzar that reads metadata and key info from our mock.
 * 
 * Need different idea to test create().
 * 
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 * 
 */
public class KeyczarToolTest extends TestCase {
  
  KeyczarReader mock;
  
  @Override
  public final void setUp() {
    mock = new MockKeyczarReader();
  }
  
  @Test
  public final void testCreate() {
    
  }
  
  @Test
  public final void testAddKey() {
    
  }
  
  @Test
  public final void testPublicKeys() {
    
  }
  
  @Test
  public final void testPromote() {
    
  }
  
  @Test
  public final void testDemote() {
    
  }
  
  @Test
  public final void testRevoke() {
    
  }
  
  @Override
  public final void tearDown() {
    
  }

}
