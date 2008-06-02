// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.exceptions.BadVersionException;
import com.google.keyczar.exceptions.InvalidSignatureException;
import com.google.keyczar.exceptions.KeyNotFoundException;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.exceptions.ShortCiphertextException;
import com.google.keyczar.interfaces.DecryptingStream;
import com.google.keyczar.interfaces.KeyczarReader;
import com.google.keyczar.interfaces.VerifyingStream;

import java.nio.ByteBuffer;

/**
 * Crypters may both encrypt and decrypt data using sets of symmetric or private
 * keys. Sets of public keys may only be used with {@link Encrypter} objects.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class Crypter extends Encrypter { 
  private static final StreamCache<DecryptingStream> CRYPT_CACHE
    = new StreamCache<DecryptingStream>();
  
  /**
   * Initialize a new Crypter with a KeyczarReader. The corresponding key set
   * must have a purpose {@link com.google.keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}.
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
   * {@link com.google.keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}.
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
    output.reset();
    byte[] outputBytes = new byte[output.remaining()];
    output.get(outputBytes);
    return outputBytes;
  }

  /**
   * Decrypt the given ciphertext input ByteBuffer and write the decrypted
   * plaintext to the output ByteBuffer 
   *  
   * @param input The input ciphertext
   * @param output The output buffer to write the decrypted plaintext
   * @throws KeyczarException If the input is malformed, the ciphertext
   * signature does not verify, the decryption key is not found, or a JCE
   * error occurs.
   */
  public void decrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException {
    if (input.remaining() < HEADER_SIZE) {
      throw new ShortCiphertextException(input.remaining());
    }
    input.mark();
    byte version = input.get();
    if (version != VERSION) {
      throw new BadVersionException(version);
    }

    byte[] hash = new byte[KEY_HASH_SIZE];
    input.get(hash);
    KeyczarKey key = getKey(hash);
    if (key == null) {
      throw new KeyNotFoundException(hash);
    }

    DecryptingStream cryptStream = CRYPT_CACHE.get(key.hashKey()); 
    if (cryptStream == null) {
      cryptStream = (DecryptingStream) key.getStream();
    }
    VerifyingStream verifyStream = cryptStream.getVerifyingStream();

    // Set the read limit to the end of the ciphertext
    if (verifyStream.digestSize() > 0) {
      if (input.remaining() < verifyStream.digestSize()) {
        throw new ShortCiphertextException(input.remaining());
      }

      input.position(input.limit() - verifyStream.digestSize());
      ByteBuffer signature = input.slice();

      // Reset the position of the input to the header
      input.reset();
      input.limit(input.limit() - verifyStream.digestSize());
      verifyStream.initVerify();
      verifyStream.updateVerify(input);
      if (!verifyStream.verify(signature)) {
        throw new InvalidSignatureException();
      }
      // Rewind back to the start of the ciphertext
      input.reset();
      input.position(input.position() + HEADER_SIZE);
    }

    cryptStream.initDecrypt(input);
    output.mark();
    cryptStream.doFinalDecrypt(input, output);
    output.limit(output.position());
    CRYPT_CACHE.put(key.hashKey(), cryptStream);
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
    return new String(decrypt(Util.base64Decode(ciphertext)));
  }

  /*
   * (non-Javadoc)
   * 
   * @see keyczar.Keyczar#isAcceptablePurpose(keyczar.KeyPurpose)
   */
  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.DECRYPT_AND_ENCRYPT;
  }
}
