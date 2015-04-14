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

import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.annotations.Experimental;
import org.keyczar.exceptions.KeyczarException;

/**
 * Data used for session based encryption. This consists of 
 * the AES key used to encrypt the plaintext and the nonce used for
 * signing.
 * 
 * The nonce should be Base64 encoded prior to being added to the
 * session material.
 * 
 * @author normandl@google.com (David Norman)
 *
 */
@Experimental
public class SessionMaterial {
  private AesKey key = null;
  private String nonce = ""; // encoded

  public SessionMaterial(AesKey key, String nonce) {
    this.key = key;
    this.nonce = nonce;
  }

  public AesKey getKey() throws KeyczarException {
    if (null == key) {
      throw new KeyczarException ("Key has not been initialized");
    }

    return key;
  }

  public String getNonce() {
    return nonce;
  }

  @Override
  public String toString() {
    try {
      return new JSONObject()
          .put("key", key != null ? key.toJson() : null)
          .put("nonce", nonce)
          .toString();
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }

  public static SessionMaterial read(String sessionString) {
    try {
      JSONObject json = new JSONObject(sessionString);
      return new SessionMaterial(
          AesKey.fromJson(json.getJSONObject("key")),
          json.getString("nonce"));
    } catch (JSONException e) {
      throw new RuntimeException(e);
    }
  }
}
