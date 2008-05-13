// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.nio.ByteBuffer;

import keyczar.internal.Constants;
import keyczar.internal.EncryptingStream;
import keyczar.internal.SigningStream;

/**
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class KeyczarEncrypter extends Keyczar {
  private KeyczarKey encryptingKey;

  public KeyczarEncrypter(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  public KeyczarEncrypter(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }
  
  /* (non-Javadoc)
   * @see keyczar.Keyczar#isAcceptablePurpose(keyczar.KeyPurpose)
   */
  @Override
  protected boolean isAcceptablePurpose(KeyPurpose purpose) {
    return purpose == KeyPurpose.ENCRYPT;
  }
  
  byte[] encrypt(byte[] input) throws KeyczarException {
    ByteBuffer output = ByteBuffer.allocate(ciphertextSize(input.length));
    encrypt(ByteBuffer.wrap(input), output);
    output.reset();
    byte[] outputBytes = new byte[output.remaining()];
    output.get(outputBytes);
    return outputBytes;
  }
  
  void encrypt(ByteBuffer input, ByteBuffer output) throws KeyczarException {
    KeyczarKey encryptingKey = getPrimaryKey();
    if (encryptingKey == null) {
      throw new KeyczarException("Need a primary key for encrypting");
    }
    EncryptingStream cryptStream = (EncryptingStream) encryptingKey.getStream();
    SigningStream signStream = cryptStream.getSigningStream();
    
    if (output.capacity() < ciphertextSize(input.remaining())) {
      throw new KeyczarException("Output buffer is too small");
    }

    output.mark();
    // Write the key header
    encryptingKey.writeHeader(output);
    
    // Write the IV. May be an empty array of zero length
    byte[] iv = cryptStream.initEncrypt();
    output.put(iv);
    cryptStream.doFinal(input, output);
    
    // The output ciphertext is between output.mark() and output.limit()
    output.limit(output.position());
    
    // Sign the ciphertext output
    signStream.initSign();
    output.reset();
    signStream.updateSign(output);
    output.limit(output.limit() + signStream.digestSize());
    signStream.sign(output);
  }
  
  int ciphertextSize(int input) throws KeyczarException {
    KeyczarKey encryptingKey = getPrimaryKey();
    if (encryptingKey == null) {
      throw new KeyczarException("Need a primary key for encrypting");
    }
    EncryptingStream cryptStream = (EncryptingStream) encryptingKey.getStream();
    SigningStream signStream = cryptStream.getSigningStream();

    return Constants.HEADER_SIZE + cryptStream.ivSize() +
        cryptStream.maxOutputSize(input) + signStream.digestSize();
  }
}
