// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import keyczar.internal.Constants;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;
import keyczar.internal.VerifyingStream;

/**
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class KeyczarVerifier extends Keyczar {
  public KeyczarVerifier(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  public KeyczarVerifier(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }
  
  @Override
  protected boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.VERIFY);
  }
  
  public boolean verify(byte[] data, byte[] signature) throws KeyczarException {
    return verify(ByteBuffer.wrap(data), ByteBuffer.wrap(signature));
  }

  public boolean verify(ByteBuffer data, ByteBuffer signature)
      throws KeyczarException {
    if (signature.remaining() < Constants.HEADER_SIZE) {
      throw new ShortSignatureException(signature.remaining());
    }
    
    byte version = signature.get();
    if (version != Constants.VERSION) {
      throw new BadVersionException(version);
    }

    byte[] hash = new byte[Constants.KEY_HASH_SIZE];
    signature.get(hash);
    KeyczarKey key = getKey(hash);

    if (key == null) {
      throw new KeyNotFoundException(hash);
    }
    
    VerifyingStream stream = (VerifyingStream) key.getStream();
    if (signature.remaining() < stream.digestSize()) {
      throw new ShortSignatureException(signature.remaining());
    }

    ByteBuffer header = ByteBuffer.allocate(Constants.HEADER_SIZE);
    key.writeHeader(header);
    header.rewind();
    stream.initVerify();
    
    stream.updateVerify(header);
    stream.updateVerify(data);
    return stream.verify(signature);
  }
}