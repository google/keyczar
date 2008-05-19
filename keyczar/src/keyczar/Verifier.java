// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import keyczar.interfaces.VerifyingStream;

// TODO: Write JavaDocs
/**
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class Verifier extends Keyczar {
  public Verifier(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  public Verifier(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }
  
  @Override
  protected boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.VERIFY ||
        purpose == KeyPurpose.SIGN_AND_VERIFY);
  }
  
  // TODO: Write JavaDocs
  public boolean verify(String data, String signature) throws KeyczarException {
    return verify(data.getBytes(), Util.base64Decode(signature));
  }
  
  // TODO: Write JavaDocs
  public boolean verify(byte[] data, byte[] signature) throws KeyczarException {
    return verify(ByteBuffer.wrap(data), ByteBuffer.wrap(signature));
  }

  // TODO: Write JavaDocs
  public boolean verify(ByteBuffer data, ByteBuffer signature)
      throws KeyczarException {
    if (signature.remaining() < HEADER_SIZE) {
      throw new ShortSignatureException(signature.remaining());
    }
    
    byte version = signature.get();
    if (version != VERSION) {
      throw new BadVersionException(version);
    }

    byte[] hash = new byte[KEY_HASH_SIZE];
    signature.get(hash);
    KeyczarKey key = getKey(hash);

    if (key == null) {
      throw new KeyNotFoundException(hash);
    }
    
    // Copy the header from the key.
    ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
    key.copyHeader(header);
    header.rewind();
    
    VerifyingStream stream = (VerifyingStream) key.getStream();
    stream.initVerify();
    stream.updateVerify(header);
    stream.updateVerify(data);
    return stream.verify(signature);
  }
}