package keyczar;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import keyczar.internal.Constants;
import keyczar.internal.SigningStream;

public class KeyczarSigner extends KeyczarVerifier {
  public KeyczarSigner(String fileLocation) throws KeyczarException {
    super(fileLocation);
  }

  public KeyczarSigner(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }
  
  @Override
  protected boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.SIGN_AND_VERIFY);
  }
  
  public byte[] sign(byte[] input) throws KeyczarException {
    ByteBuffer output = ByteBuffer.allocate(digestSize());
    sign(ByteBuffer.wrap(input), output);
    return output.array();
  }
  
  public void sign(ByteBuffer input, ByteBuffer output)
      throws KeyczarException {
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    SigningStream stream = (SigningStream) signingKey.getStream();

    if (output.capacity() < digestSize()) {
      throw new ShortBufferException(output.capacity(), digestSize());
    }
    ByteBuffer header = ByteBuffer.allocate(Constants.HEADER_SIZE);
    signingKey.writeHeader(header);
    header.rewind();
    stream.initSign();
    
    // Sign the header and write it to the output buffer
    output.mark();
    output.put(header);
    header.rewind();
    stream.updateSign(header);
    
    // Write the signature to the output
    stream.updateSign(input);
    stream.sign(output);
    output.limit(output.position());
  }
  
  public int digestSize() throws KeyczarException {
    KeyczarKey signingKey = getPrimaryKey();
    if (signingKey == null) {
      throw new NoPrimaryKeyException();
    }
    return Constants.HEADER_SIZE +
        ((SigningStream) signingKey.getStream()).digestSize();
  }
}
