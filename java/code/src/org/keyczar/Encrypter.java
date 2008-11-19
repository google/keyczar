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

import org.apache.log4j.Logger;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.NoPrimaryKeyException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.EncryptingStream;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.util.Base64Coder;

import java.nio.ByteBuffer;

/**
 * Encrypters are used strictly to encrypt data. Typically, Encrypters will read
 * sets of public keys, although may also be instantiated with sets of symmetric
 * keys.
 *
 * {@link Crypter} objects should be used with symmetric or private key sets to
 * decrypt data.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Encrypter extends Keyczar {
  private static final Logger ENCRYPTER_LOGGER =
    Logger.getLogger(Encrypter.class);
  private static final int ENCRYPT_CHUNK_SIZE = 1024;
  private final StreamQueue<EncryptingStream> ENCRYPT_QUEUE =
    new StreamQueue<EncryptingStream>();

  /**
   * Initialize a new Encrypter with a KeyczarReader. The corresponding key set
   * must have a purpose of either
   * {@link org.keyczar.enums.KeyPurpose#ENCRYPT} or
   * {@link org.keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}.
   *
   * @param reader A reader to read keys from
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Encrypter(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  /**
   * Initialize a new Encrypter with a key set location. This will attempt to
   * read the keys using a KeyczarFileReader. The corresponding key set
   * must have a purpose of either
   * {@link org.keyczar.enums.KeyPurpose#ENCRYPT} or
   * {@link org.keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}
   *
   * @param fileLocation Directory containing a key set
   * @throws KeyczarException In the event of an IO error reading keys or if the
   * key set does not have the appropriate purpose.
   */
  public Encrypter(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }
  
  /**
   * Returns the size of the ciphertext output that would result from encrypting
   * an input of the given length.
   *
   * @param inputLength The length of the input.
   * @return Length of the ciphertext that would be produced.
   * @throws KeyczarException If the key set contains no primary encrypting key.
   */
  public int ciphertextSize(int inputLength) throws KeyczarException {
    EncryptingStream cryptStream = ENCRYPT_QUEUE.poll();
    if (cryptStream == null) {
      KeyczarKey encryptingKey = getPrimaryKey();
      if (encryptingKey == null) {
        throw new NoPrimaryKeyException();
      }
      cryptStream = (EncryptingStream) encryptingKey.getStream();
    }
    SigningStream signStream = cryptStream.getSigningStream();

    int outputSize = HEADER_SIZE + cryptStream.maxOutputSize(inputLength) +
        signStream.digestSize();
    ENCRYPT_QUEUE.add(cryptStream);
    return outputSize;
  }

  /**
   * Encrypt the given input byte array.
   *
   * @param input The input to encrypt
   * @return The encrypted ciphertext
   * @throws KeyczarException If there is a JCE exception or the key set does
   * not contain a primary encrypting key.
   */
  public byte[] encrypt(byte[] input) throws KeyczarException {
    ByteBuffer output = ByteBuffer.allocate(ciphertextSize(input.length));
    encrypt(ByteBuffer.wrap(input), output);
    output.reset();
    byte[] outputBytes = new byte[output.remaining()];
    output.get(outputBytes);
    return outputBytes;
  }

  /**
   * Encrypt the given input ByteBuffer.
   *
   * @param input The input buffer to encrypt. Will not be modified
   * @param output The buffer to write the output ciphertext to.
   * @throws KeyczarException If there is a JCE exception, the key set does
   * not contain a primary encrypting key, or the output buffer is too small.
   */
  public void encrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException {
    ENCRYPTER_LOGGER.info(Messages.getString("Encrypter.Encrypting", input.remaining()));
    KeyczarKey encryptingKey = getPrimaryKey();
    if (encryptingKey == null) {
      throw new NoPrimaryKeyException() ;
    }
    EncryptingStream cryptStream = ENCRYPT_QUEUE.poll();
    if (cryptStream == null) {
      cryptStream = (EncryptingStream) encryptingKey.getStream();
    }
    // Initialize the signing stream
    SigningStream signStream = cryptStream.getSigningStream();
    signStream.initSign();

    // Write the key header
    output.mark();
    ByteBuffer outputToSign = output.asReadOnlyBuffer();
    encryptingKey.copyHeader(output);

    // Write the IV. May be an empty array of zero length
    cryptStream.initEncrypt(output);

    ByteBuffer inputCopy = input.asReadOnlyBuffer();
    while (inputCopy.remaining() > ENCRYPT_CHUNK_SIZE) {
      ByteBuffer inputChunk = inputCopy.slice();
      inputChunk.limit(ENCRYPT_CHUNK_SIZE);
      cryptStream.updateEncrypt(inputChunk, output);
      inputCopy.position(inputCopy.position() + ENCRYPT_CHUNK_SIZE);

      outputToSign.limit(output.position());
      signStream.updateSign(outputToSign);
      outputToSign.position(output.position());
    }

    // Sign any remaining plaintext
    cryptStream.doFinalEncrypt(inputCopy, output);
    output.limit(output.position() + signStream.digestSize());

    // Set the limit on the output to sign
    outputToSign.limit(output.position());
    signStream.updateSign(outputToSign);
    // Sign the final block of ciphertext output
    signStream.sign(output);
    ENCRYPT_QUEUE.add(cryptStream);
  }

  /**
   * Encrypt a String and return a web-safe Base64 encoded ciphertext.
   *
   * @param input An String to encrypt.
   * @return A web-safe Base64 encoded ciphertext.
   * @throws KeyczarException If there is a JCE exception or the key set does
   * not contain a primary encrypting key.
   */
  public String encrypt(String input) throws KeyczarException {
    return Base64Coder.encode(encrypt(input.getBytes()));
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.ENCRYPT
        || purpose == KeyPurpose.DECRYPT_AND_ENCRYPT;
  }
}