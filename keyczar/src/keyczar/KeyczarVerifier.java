// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

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
  public enum VerifyResult {
    UNSIGNED,
    FAILED,
    KEY_UNAVAILABLE,
    MALFORMED,
    VERIFIED,
  }
  
  public KeyczarVerifier(String fileLocation) {
    super(fileLocation);
  }

  public KeyczarVerifier(KeyczarReader reader) {
    super(reader);
  }
  
  @Override
  protected boolean isAcceptablePurpose(KeyPurpose purpose) {
    return (purpose == KeyPurpose.VERIFY);
  }
  
  public boolean verify(byte[] data, byte[] signature) throws KeyczarException {
    return verify(data, 0, data.length, signature, 0) == VerifyResult.VERIFIED;
  }

  public VerifyResult verify(byte[] data, int dataOffset, int dataLen,
      byte[] signature, int signatureOffset)
      throws KeyczarException {
    if (signature.length - signatureOffset < Constants.HEADER_SIZE ||
        signature[signatureOffset] != Constants.VERSION) {
      return VerifyResult.MALFORMED;
    }

    byte[] hash = new byte[Constants.KEY_HASH_SIZE];
    System.arraycopy(signature, signatureOffset + 1,
        hash, 0, Constants.KEY_HASH_SIZE);
    KeyczarKey key = getKey(hash);

    if (key == null) {
      return VerifyResult.KEY_UNAVAILABLE;
    }
    
    VerifyingStream stream = (VerifyingStream) key.getStream();
    int sigSize = Constants.HEADER_SIZE + stream.digestSize();
    if (signature.length - signatureOffset < sigSize) {
      return VerifyResult.MALFORMED;
    }

    stream.initVerify();
    stream.updateVerify(signature, signatureOffset, Constants.HEADER_SIZE);
    stream.updateVerify(data, dataOffset, dataLen);
    if (stream.verify(signature, Constants.HEADER_SIZE)) {
      return VerifyResult.VERIFIED;
    } else {
      return VerifyResult.FAILED;
    }
  }
}