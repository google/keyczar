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


import junit.framework.Test;
import junit.framework.TestSuite;

import org.apache.log4j.PropertyConfigurator;
import org.keyczar.experimental.UriSignerTest;

/**
 * Suite of all unit tests.
 * 
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public class AllTests extends TestSuite {
  static {
    PropertyConfigurator.configure("./tests/log4j.properties");
  }
  
  public static Test suite() {
    TestSuite suite = new TestSuite();
    suite.addTestSuite(CrypterTest.class);
    suite.addTestSuite(SignerTest.class);
    suite.addTestSuite(TimeoutSignerTest.class);
    suite.addTestSuite(UriSignerTest.class);
    suite.addTestSuite(KeyczarToolTest.class);
    suite.addTestSuite(I18nTest.class);
    return suite;
  }
}