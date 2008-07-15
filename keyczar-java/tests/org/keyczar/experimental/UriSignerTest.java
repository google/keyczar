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

package org.keyczar.experimental;


import junit.framework.TestCase;

import org.junit.Test;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.experimental.UriSigner;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Tests UriSigner utility.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 */

public class UriSignerTest extends TestCase {
  String[] testUris = { "www.foo.com", "http://www.foo.com/bar#foo",
    "http://foo.com/q?a=1&b=2&c=3", "http://foo.com/q?c=3&b=2&a=1",
    "http://foo.com/q?c=3&b=2&a=1#blah"
  };
  UriSigner uriSigner;
  
  @Override
  public final void setUp() throws KeyczarException {
    uriSigner = new UriSigner("./testdata/hmac");
  }
  
  @Test
  public final void testSignAndVerifyUri() throws KeyczarException,
      URISyntaxException {
    for (String uri : testUris) {
      URI signedUri = uriSigner.sign(new URI(uri));
      assertTrue(uriSigner.verify(signedUri));
    }
  }
  
  /**
   * Tests that the signatures on two URIs with the same canonical
   * representation are indeed the same.
   * 
   * @throws KeyczarException
   * @throws URISyntaxException
   */
  @Test
  public final void testCanonicalUri() throws KeyczarException, 
      URISyntaxException {
    // A and B are same URIs with query parameters in different orders
    URI signedUriA = uriSigner.sign(new URI(testUris[2]));
    URI signedUriB = uriSigner.sign(new URI(testUris[3]));
    // the signature parameter should be the same
    assertEquals(signedUriA.toASCIIString(), signedUriB.toASCIIString());
  }
  
  @Override
  public final void tearDown() {
    uriSigner = null;
  }
}