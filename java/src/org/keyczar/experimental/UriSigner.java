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


import org.keyczar.Signer;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.TreeSet;

/**
 * Adds a signature parameter, named sig by default, to a URI query which
 * signs all the query parameters. Can use to check integrity of query
 * parameters. Canonicalizes URI query parameters to be in lexicographic order.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
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

  /**
   * Returns a signed URI with the signature in the default parameter 'sig'.
   * Rest of the URI and query parameters are unchanged. Entire URI is signed.
   *
   * @param uri to be signed
   * @return signed uri
   * @throws KeyczarException
   */
  public URI sign(URI uri) throws KeyczarException {
    return sign(uri, DEFAULT_SIG_PARAM);
  }

  /**
   * Returns a signed URI with the signature in a parameter with the specified
   * name. Rest of the URI and query parameters are unchanged.
   * Entire URI is signed.
   *
   * @param uri to be signed
   * @param sigParam String name of signature parameter
   * @return signed uri with signature in given parameter
   * @throws KeyczarException
   */
  public URI sign(URI uri, String sigParam) throws KeyczarException {
    try {
      uri = canonicalUri(uri);
    } catch (URISyntaxException e) {
      throw new KeyczarException(e);
    }
    String uriString = uri.toASCIIString();
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

  /**
   * Verifies that the given URI is properly signed. Assumes signature is
   * in query parameter named 'sig'.
   *
   * @param signedUri
   * @return true if signature is valid, false otherwise
   * @throws KeyczarException
   */
  public boolean verify(URI signedUri) throws KeyczarException {
    return verify(signedUri, DEFAULT_SIG_PARAM);
  }

  /**
   * Verifies that the given URI is properly signed. Takes signature from
   * from the parameter name given.
   *
   * @param signedUri
   * @param sigParam
   * @return true if signature is valid, false otherwise
   * @throws KeyczarException
   */
  public boolean verify(URI signedUri, String sigParam)
      throws KeyczarException {
    if (signedUri == null) {
      return false;
    }
    String query = signedUri.getQuery();
    if (query == null) {
      return false;
    }
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
        unsignedQuery.deleteCharAt(unsignedQuery.length() - 1); // extra &
        unsignedUri = new URI(signedUri.getScheme(), signedUri.getAuthority(),
            signedUri.getPath(), unsignedQuery.toString(),
            signedUri.getFragment());
      } else {
        unsignedUri = new URI(signedUri.getScheme(), signedUri.getAuthority(),
            signedUri.getPath(), null, signedUri.getFragment());
      }
      unsignedUri = canonicalUri(unsignedUri); // CHECK: use canonical version
      return signer.verify(unsignedUri.toASCIIString(), sig);
    } catch (URISyntaxException e) {
      // Throw an exception?
      return false;
    }
  }

  /**
   * Return canonical version of query string with all query parameters sorted
   * in lexicographic order.
   *
   * @param query to canonicalize
   * @return canonicalized query String
   */
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

  /**
   * Canonicalizes URI by replacing query component with canonicalized query.
   *
   * @param uri to be canonicalized
   * @return canonicalized uri
   * @throws URISyntaxException if uri is invalid
   */
  private URI canonicalUri(URI uri) throws URISyntaxException {
    return (uri == null) ? null : new URI(uri.getScheme(), uri.getAuthority(),
        uri.getPath(), canonicalQuery(uri.getQuery()), uri.getFragment());
  }
}