// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.nio.ByteBuffer;

import keyczar.enums.KeyPurpose;
import keyczar.interfaces.EncryptingStream;
import keyczar.interfaces.KeyczarReader;
import keyczar.interfaces.SigningStream;

/**
 * Encrypters are used strictly to encrypt data. Typically, Encrypters will read
 * sets of public keys, although may also be instantiated with sets of symmetric
 * keys.
 * 
 * {@link Crypter} objects should be used with symmetric or private key sets to
 * decrypt data.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class Encrypter extends Keyczar {
  /**
   * Initialize a new Encrypter with a KeyczarReader. The corresponding key set
   * must have a purpose of either {@link keyczar.enums.KeyPurpose#ENCRYPT} or
   * {@link keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}.
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
   * must have a purpose of either {@link keyczar.enums.KeyPurpose#ENCRYPT} or
   * {@link keyczar.enums.KeyPurpose#DECRYPT_AND_ENCRYPT}
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
    KeyczarKey encryptingKey = getPrimaryKey();
    if (encryptingKey == null) {
      throw new KeyczarException("Need a primary key for encrypting");
    }
    EncryptingStream cryptStream = (EncryptingStream) encryptingKey.getStream();
    SigningStream signStream = cryptStream.getSigningStream();

    return HEADER_SIZE + cryptStream.ivSize()
        + cryptStream.maxOutputSize(inputLength) + signStream.digestSize();
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
   * @param input The input buffer to encrypt.
   * @param output The buffer to write the output ciphertext to.
   * @throws KeyczarException If there is a JCE exception, the key set does
   * not contain a primary encrypting key, or the output buffer is too small.
   */
  public void encrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException {
    KeyczarKey encryptingKey = getPrimaryKey();
    if (encryptingKey == null) {
      throw new KeyczarException("Need a primary key for encrypting");
    }    
    if (output.capacity() < ciphertextSize(input.remaining())) {
      throw new KeyczarException("Output buffer is too small");
    }

    // Write the key header
    output.mark();
    encryptingKey.copyHeader(output);

    // Write the IV. May be an empty array of zero length
    EncryptingStream cryptStream = (EncryptingStream) encryptingKey.getStream();
    byte[] iv = cryptStream.initEncrypt();
    output.put(iv);
    cryptStream.doFinalEncrypt(input, output);

    // The output ciphertext is between output.mark() and output.limit()
    output.limit(output.position());

    SigningStream signStream = cryptStream.getSigningStream();

    // Sign the ciphertext output
    signStream.initSign();
    output.reset();
    signStream.updateSign(output);
    output.limit(output.limit() + signStream.digestSize());
    signStream.sign(output);
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
    return Util.base64Encode(encrypt(input.getBytes()));
  }

  /*
   * (non-Javadoc)
   * 
   * @see keyczar.Keyczar#isAcceptablePurpose(keyczar.KeyPurpose)
   */
  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.ENCRYPT
        || purpose == KeyPurpose.DECRYPT_AND_ENCRYPT;
  }
}