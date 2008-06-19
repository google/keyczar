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

package com.google.keyczar.experimental;

import com.google.keyczar.Signer;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.KeyczarReader;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.TreeSet;

/**
 * Under construction. This class will most likely change.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class UriSigner {
  private static final String DEFAULT_SIG_PARAM = "sig";
  private Signer signer;

  public UriSigner(KeyczarReader reader) throws KeyczarException {
    signer = new Signer(reader);
  }

  public UriSigner(String fileLocation) throws KeyczarException {
    signer = new Signer(fileLocation);
  }
  
  public URI sign(URI uri) throws KeyczarException { 
    return sign(uri, DEFAULT_SIG_PARAM);
  }
  
  public URI sign(URI uri, String sigParam) throws KeyczarException {
    String uriString = uri.toASCIIString();
    // TODO: Canonicalize the URI
    String sig = signer.sign(uriString);
    String signedQuery = sigParam + "=" + sig;
    String query = uri.getQuery();
    if (query != null) {
      signedQuery = query + "&" + signedQuery;
    }

    try {
      return new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(),
          signedQuery, uri.getFragment());
    } catch (URISyntaxException e) {
      throw new KeyczarException(e);
    }
  }
  
  public boolean verify(URI signedUri) throws KeyczarException {
    return verify(signedUri, DEFAULT_SIG_PARAM);
  }
  
  public boolean verify(URI signedUri, String sigParam)
      throws KeyczarException {
    String query = signedUri.getQuery();
    String sig = null;
    StringBuffer unsignedQuery = new StringBuffer();
    
    for (String param : query.split("&")) {
      if (param.startsWith(sigParam)) {
        String[] nameValue = param.split("=");
        if (nameValue.length == 2) {
          sig = nameValue[1];
        }
      } else {
        unsignedQuery.append(param).append('&');
      }
    }
    if (sig == null) {
      return false;
    }
    
    try {
      URI unsignedUri;
      if (unsignedQuery.length() > 0) {
        unsignedQuery.deleteCharAt(unsignedQuery.length() - 1);
        unsignedUri = new URI(signedUri.getScheme(), signedUri.getAuthority(),
            signedUri.getPath(), unsignedQuery.toString(), signedUri.getFragment());
      } else {
        unsignedUri = new URI(signedUri.getScheme(), signedUri.getAuthority(),
            signedUri.getPath(), null, signedUri.getFragment());
      }
      return signer.verify(unsignedUri.toASCIIString(), sig);
    } catch (URISyntaxException e) {
      // Throw an exception?
      return false;
    }
  }

  
  private String canonicalQuery(String query) {
    StringBuffer canonicalQuery = new StringBuffer();

    TreeSet<String> params = new TreeSet<String>();
    if (query != null) {
      String[] nameValues = query.split("&");
      for (String nameValue : nameValues) {
        params.add(nameValue);
      }
      for (String nameValue : params) {
        canonicalQuery.append(nameValue).append('&');
      }
      // Trim the trailing '&'
      canonicalQuery.deleteCharAt(canonicalQuery.length() - 1);
    }
    return canonicalQuery.toString();
  }
}
