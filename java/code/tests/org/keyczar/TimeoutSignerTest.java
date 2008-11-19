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


import junit.framework.TestCase;

import org.junit.Test;
import org.keyczar.exceptions.KeyczarException;

/**
 * Tests Signer class for signing and verifying timeout signatures
 * with HMAC, RSA, and DSA.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public class TimeoutSignerTest extends TestCase {
  private static final String TEST_DATA = "./testdata";
  private String input = "This is some test data";

  private final void testTimeoutSignAndVerify(TimeoutSigner signer)
      throws KeyczarException, InterruptedException {
    long now = System.currentTimeMillis();
    // Create a signature that will be valid for a long time
    String sig = signer.timeoutSign(input, now + 10000000);
    assertTrue(signer.verify(input, sig));
    
    // Create a signature that is already expired
    sig = signer.timeoutSign(input, now - 1000);
    assertFalse(signer.verify(input, sig));
    
    
    // Create a valid signature, let it expire, and check that it is now invalid
    sig = signer.timeoutSign(input, now + 1000);
    assertTrue(signer.verify(input, sig));
    Thread.sleep(1000);
    assertFalse(signer.verify(input, sig));    
  }
  
  @Test
  public final void testHmac() throws KeyczarException,
      InterruptedException {
    TimeoutSigner signer = new TimeoutSigner(TEST_DATA + "/hmac");
    testTimeoutSignAndVerify(signer);
  }
  
  @Test
  public final void testDsa() throws KeyczarException,
      InterruptedException {
    TimeoutSigner signer = new TimeoutSigner(TEST_DATA + "/dsa");
    testTimeoutSignAndVerify(signer);
  }
  
  @Test
  public final void testRsa() throws KeyczarException,
      InterruptedException {
    TimeoutSigner signer = new TimeoutSigner(TEST_DATA + "/rsa-sign");
    testTimeoutSignAndVerify(signer);
  }
}