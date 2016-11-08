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

import org.keyczar.enums.KeyPurpose;
import org.keyczar.exceptions.BadVersionException;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortSignatureException;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

/**
* Verifiers are used strictly to verify signatures. Typically, Verifiers will
* read sets of public keys, although may also be instantiated with sets of
* symmetric or private keys.
*
* {@link Signer} objects should be used with symmetric or private key sets to
* generate signatures.
*
* @author steveweis@gmail.com (Steve Weis)
*
*/
public class Verifier extends Keyczar {

  /**
   * Initialize a new Verifier with a KeyczarReader. The corresponding key set
   * must have a purpose of either {@link org.keyczar.enums.KeyPurpose#VERIFY} or
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Verifier(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new Verifier with a key set location. This will attempt to
   * read the keys using a KeyczarFileReader. The corresponding key set
   * must have a purpose of either
   * {@link org.keyczar.enums.KeyPurpose#VERIFY} or
   * {@link org.keyczar.enums.KeyPurpose#SIGN_AND_VERIFY}
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Verifier(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  /**
   * Verifies a signature on the given byte array of data
   *
   * @param data The data to verify the signature on
   * @param signature The signture to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(byte[] data, byte[] signature) throws KeyczarException {
    return verify(ByteBuffer.wrap(data), ByteBuffer.wrap(signature));
  }

  /**
   * Verifies the signature on the data stored in the given ByteBuffer
   *
   * @param data The data to verify the signature on
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(ByteBuffer data, ByteBuffer signature)
      throws KeyczarException {
    return verify(data, null, signature);
  }

  /**
   * Verifies the signature on the data stored in the given ByteBuffer
   *
   * @param data The data to verify the signature on
   * @param hidden Any hidden data to include in the signature
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  boolean verify(ByteBuffer data, ByteBuffer hidden,
      ByteBuffer signature) throws KeyczarException {
    if (signature.remaining() < HEADER_SIZE) {
      throw new ShortSignatureException(signature.remaining());
    }

    byte[] hash = checkFormatAndGetHash(signature);
    Iterable<KeyczarKey> keys = getVerifyingKey(hash);

    if (keys == null) {
      throw new KeyNotFoundException(hash);
    }
    
    data.mark();
    if (hidden != null) {
      hidden.mark();
    }
    signature.mark();
    for (KeyczarKey key : keys) {
      try {
        if (rawVerify(key, data, hidden, signature)) {
          return true;
        }
      } catch (KeyczarException e) {
        //Continue Checking keys in case of collision
      } catch (RuntimeException e) {
        //Unfortunately Java crypto apis can throw runtime exceptions
      }
      data.reset();
      if (hidden != null) {
        hidden.reset();
      }
      signature.reset();
    }
    return false;
  }


  /**
   * Verifies the signature on the given String
   *
   * @param data The data to verify the signature on
   * @param signature The signature to verify
   * @return Whether this is a valid signature
   * @throws KeyczarException If the signature is malformed or a JCE error
   * occurs.
   */
  public boolean verify(String data, String signature) throws KeyczarException {
    try {
      return verify(data.getBytes(DEFAULT_ENCODING),
          Base64Coder.decodeWebSafe(signature));
    } catch (UnsupportedEncodingException e) {
      throw new KeyczarException(e);
    }
  }

  /*
   * perform a verification, assume all key and hash checks have been performed.
   */
  boolean rawVerify(KeyczarKey key, final ByteBuffer data, final ByteBuffer hidden,
      final ByteBuffer signature) throws KeyczarException {
      VerifyingStream stream = (VerifyingStream) key.getStream();

      stream.initVerify();
      stream.updateVerify(data);
      if (hidden != null) {
        stream.updateVerify(hidden);
      }

      // The signed data is terminated with the current Keyczar format 
      stream.updateVerify(ByteBuffer.wrap(FORMAT_BYTES));

      boolean result = stream.verify(signature);
      key.addStreamToCacheForReuse(stream);
      return result;
  }

  /**
   * Verifies an attached signature. The input signed blob contains both the
   * data and its signature.
   *
   * Data should be decoded prior to method entry.
   *
   * @param signedBlob Data and signature to be verified
   * @param hidden Hidden data or nonce included in a signature
   * @return The result of the verification
   * @throws KeyczarException If an error occurred while
   *    signing key was verifying the signature.
   */
  public boolean attachedVerify(final byte[] signedBlob,
      final byte[] hidden) throws KeyczarException {
    ByteBuffer sigBuffer = ByteBuffer.wrap(signedBlob);
    // assume I need to decode here as well.
    byte[] hash = checkFormatAndGetHash(sigBuffer);

    // we have stripped the format and hash, now just get the blob and
    // raw signature
    int blobSize = sigBuffer.getInt();
    byte[] blob = new byte[blobSize];
    sigBuffer.get(blob);
    int signatureSize = sigBuffer.remaining();
    byte[] signature = new byte[signatureSize];
    sigBuffer.get(signature);

    // the signed mass to verify is:
    // [blob | hidden.length | hidden | format] or [blob | 0 | format]
    byte[] hiddenPlusLength = Util.fromInt(0);
    if (hidden.length > 0) {
      hiddenPlusLength = Util.lenPrefix(hidden);
    }
    
    Iterable<KeyczarKey> keys = getVerifyingKey(hash);
    for (KeyczarKey key : keys) {
      try {
        if (rawVerify(key, ByteBuffer.wrap(blob), ByteBuffer.wrap(hiddenPlusLength), 
            ByteBuffer.wrap(signature))) {
          return true;
        }
      } catch (KeyczarException e) {
            //continue checking keys incase of collision
      } catch (RuntimeException e) {
            //unfortunately java crypto apis can throw a runtime exception
      } 
    }
    
    return false;
  }

  /**
   * Verify the signature on a signed blob of data and return the data. If the
   * signature fails to verify, then throw a KeyczarException
   *
   * Data should be decoded prior to method entry.
   *
   * @param signedBlob A signed blob to verify.
   * @param hidden Hidden data or nonce included in the signature
   * @return The contents of the signed blob, only if the signature verifies
   * @throws KeyczarException If the signature fails to verify.
   */
  public byte[] getAttachedData(final byte[] signedBlob,
        final byte[] hidden) throws KeyczarException {
    if (!attachedVerify(signedBlob, hidden)) {
      throw new KeyczarException("Attached signature failed to verify." +
          " Unable to return signed data.");
    }

    // The call to attachedVerify will ensure that the encoded blob length is
    // not out of bounds. If it is, a malformed result will be returned.
    return getAttachedDataWithoutVerifying(signedBlob);
  }

  /**
   * Gets the signed blob of data, without checking the signature.
   *
   * Data should be decoded prior to method entry.
   *
   * @param signedBlob A signed blob to extract data from.
   * @return The contents of the signed blob.
   * @throws KeyczarException if unable to get attached blob.
   */
  public byte[] getAttachedDataWithoutVerifying(final byte[] signedBlob)
      throws KeyczarException {
    ByteBuffer sigBuffer = ByteBuffer.wrap(signedBlob);

    byte[] hash = checkFormatAndGetHash(sigBuffer);
    // just get the bits even though we won't use it.
    getVerifyingKey(hash);

    // we have stripped the format and hash, now just get the blob and
    // raw signature
    int blobSize = sigBuffer.getInt();
    byte[] blob = new byte[blobSize];
    sigBuffer.get(blob);

    return blob;
  }

  private byte[] checkFormatAndGetHash(ByteBuffer signature)
      throws BadVersionException {
    byte version = signature.get();
    if (version != FORMAT_VERSION) {
      throw new BadVersionException(version);
    }

    byte[] hash = new byte[KEY_HASH_SIZE];
    signature.get(hash);

    return hash;
  }

  private Iterable<KeyczarKey> getVerifyingKey(byte[] hash) throws KeyNotFoundException {
    Iterable<KeyczarKey> key = getKey(hash);

    if (key == null) {
      throw new KeyNotFoundException(hash);
    }

    return key;
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.VERIFY ||
            purpose == KeyPurpose.SIGN_AND_VERIFY);
  }
}
