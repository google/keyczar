package com.google.security.keyczar.uriutil;

import static org.junit.Assert.assertTrue;

import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.uriutil.UriSigner;

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
