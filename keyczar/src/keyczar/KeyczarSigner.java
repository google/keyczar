package keyczar;

import java.io.UnsupportedEncodingException;
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
    return sign(input, 0, input.length);
  }
  
  public byte[] sign(byte[] input, int inputOffset, int inputLength)
      throws KeyczarException {
    KeyczarKey key = getPrimaryKey();
    if (key == null) {
      throw new KeyczarException("Need a primary key for signing");
    }
    SigningStream stream = (SigningStream) key.getStream();
    // Allocate space for a version byte, key ID, and raw digest
    byte[] keyHash = key.hash();
    byte[] outputSig =
      new byte[1 + keyHash.length + stream.digestSize()];
    int written = 0;
    outputSig[written++] = Constants.VERSION;
    System.arraycopy(keyHash, 0, outputSig, written, keyHash.length);
    written += keyHash.length;
    
    stream.initSign();
    // Sign the version byte and the hash
    stream.updateSign(outputSig, 0, written);
    stream.updateSign(input, inputOffset, inputLength);
    stream.sign(outputSig, written);
    return outputSig;
  }
}
