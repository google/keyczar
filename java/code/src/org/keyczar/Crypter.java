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
import org.keyczar.exceptions.InvalidSignatureException;
import org.keyczar.exceptions.KeyNotFoundException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.ShortCiphertextException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.DecryptingStream;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.util.Base64Coder;

import java.nio.ByteBuffer;
import java.util.Collection;

/**
 * Crypters may both encrypt and decrypt data using sets of symmetric or private
 * keys. Sets of public keys may only be used with {@link Encrypter} objects.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Crypter extends Encrypter {
  private static final int DECRYPT_CHUNK_SIZE = 1024;

  /**
   * Initialize a new Crypter with a KeyczarReader. The corresponding key set
   * must have a purpose {@link org.keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Crypter(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new Crypter with a key set location. This will attempt to
   * read the keys using a KeyczarFileReader. The corresponding key set
   * must have a purpose of
   * {@link org.keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}.
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Crypter(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  /**
   * Decrypt the given byte array of ciphertext
   *
   * @param input The input ciphertext
   * @return The decrypted plaintext
   * @throws KeyczarException If the input is malformed, the ciphertext
   * signature does not verify, the decryption key is not found, or a JCE
   * error occurs.
   */
  public byte[] decrypt(byte[] input) throws KeyczarException {
    ByteBuffer output = ByteBuffer.allocate(input.length);
    decrypt(ByteBuffer.wrap(input), output);
    output.rewind();
    byte[] outputBytes = new byte[output.remaining()];
    output.get(outputBytes);
    return outputBytes;
  }

  /**
   * Decrypt the given ciphertext input ByteBuffer and write the decrypted
   * plaintext to the output ByteBuffer
   *
   * @param input The input ciphertext. Will not be modified.
   * @param output The output buffer to write the decrypted plaintext
   * @throws KeyczarException If the input is malformed, the ciphertext
   * signature does not verify, the decryption key is not found, or a JCE
   * error occurs.
   */
  public void decrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException {
    ByteBuffer inputCopy = input.asReadOnlyBuffer();
    if (inputCopy.remaining() < HEADER_SIZE) {
      throw new ShortCiphertextException(inputCopy.remaining());
    }
    byte version = inputCopy.get();
    if (version != FORMAT_VERSION) {
      throw new BadVersionException(version);
    }

    byte[] hash = new byte[KEY_HASH_SIZE];
    inputCopy.get(hash);
    Collection<KeyczarKey> keys  = getKey(hash);
    if (keys == null) {
      throw new KeyNotFoundException(hash);
    }

    // The input to decrypt is now positioned at the start of the ciphertext
    inputCopy.mark();
    int inputLimit = inputCopy.limit();
    KeyczarException error = null;
    
    boolean collision = keys.size() > 1;
    
    for (KeyczarKey key : keys) {
      error = null;
      
      ByteBuffer tempBuffer = output;
      if (collision) {
        tempBuffer = ByteBuffer.allocate(output.remaining());
      }
      
      DecryptingStream cryptStream = (DecryptingStream) key.getStream();
      
      try {
        VerifyingStream verifyStream = cryptStream.getVerifyingStream();
        if (inputCopy.remaining() < verifyStream.digestSize()) {
          throw new ShortCiphertextException(inputCopy.remaining());
        }

        // Slice off the signature into another buffer
        inputCopy.position(inputCopy.limit() - verifyStream.digestSize());
        ByteBuffer signature = inputCopy.slice();

        // Reset the position of the input to start of the ciphertext
        inputCopy.reset();
        inputCopy.limit(inputCopy.limit() - verifyStream.digestSize());

        // Initialize the crypt stream. This may read an IV if any.
        cryptStream.initDecrypt(inputCopy);

        // Verify the header and IV if any
        ByteBuffer headerAndIvToVerify = input.asReadOnlyBuffer();
        headerAndIvToVerify.limit(inputCopy.position());
        verifyStream.initVerify();
        verifyStream.updateVerify(headerAndIvToVerify);

        tempBuffer.mark();
        // This will process large input in chunks, rather than all at once. This
        // avoids making two passes through memory.
        while (inputCopy.remaining() > DECRYPT_CHUNK_SIZE) {
          ByteBuffer ciphertextChunk = inputCopy.slice();
          ciphertextChunk.limit(DECRYPT_CHUNK_SIZE);
          cryptStream.updateDecrypt(ciphertextChunk, output);
          ciphertextChunk.rewind();
          verifyStream.updateVerify(ciphertextChunk);
          inputCopy.position(inputCopy.position() + DECRYPT_CHUNK_SIZE);
        }
        int lastBlock = inputCopy.position();
        verifyStream.updateVerify(inputCopy);
        if (!verifyStream.verify(signature)) {
          throw new InvalidSignatureException();
        }
        inputCopy.position(lastBlock);
        cryptStream.doFinalDecrypt(inputCopy, tempBuffer);
        tempBuffer.limit(tempBuffer.position());
        if (collision) {
          //Success copy to final output buffer
          tempBuffer.rewind();
          output.put(tempBuffer);
          output.limit(output.position());
        }
        key.addStreamToCacheForReuse(cryptStream);
        return;
      } catch (KeyczarException e) {
        error = e;
      } catch (RuntimeException e) {
        error = new InvalidSignatureException();
      } finally {
        inputCopy.reset();
        inputCopy.limit(inputLimit);
      }
    }
    if (error != null) {
      throw error;
    }
  }

  /**
   * Decrypt the given web-safe Base64 encoded ciphertext and return the
   * decrypted plaintext as a String.
   *
   * @param ciphertext The encrypted ciphertext in web-safe Base64 format
   * @return The decrypted plaintext as a string
   * @throws KeyczarException If the input is malformed, the ciphertext
   * signature does not verify, the decryption key is not found, the input is
   * not web-safe Base64 encoded, or a JCE error occurs.
   */
  public String decrypt(String ciphertext) throws KeyczarException {
    return new String(decrypt(Base64Coder.decodeWebSafe(ciphertext)));
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.DECRYPT_AND_ENCRYPT;
  }
}
