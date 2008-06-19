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

package com.google.security.keyczar.experimental;

import static org.junit.Assert.assertTrue;

import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.experimental.UriSigner;

import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;


public class UriSignerTest {
  String[] testUris = { "www.foo.com", "http://www.foo.com/bar#foo",
    "http://foo.com/q?a=1&b=2&c=3", "http://foo.com/q?c=3&b=2&a=1",
    "http://foo.com/q?c=3&b=2&a=1#blah"
  };
  
  @Test
  public final void testSignAndVerifyURI() throws KeyczarException,
      URISyntaxException {
    UriSigner uriSigner = new UriSigner("./testdata/hmac");
    
    for (String uri : testUris) {
      URI signedUri = uriSigner.sign(new URI(uri));
      assertTrue(uriSigner.verify(signedUri));
    }
  }
}
