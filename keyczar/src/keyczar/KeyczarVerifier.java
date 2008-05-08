// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;

import keyczar.internal.Constants;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;
import keyczar.internal.VerifyingStream;

/**
 * @author steveweis@gmail.com (Steve Weis)
 *
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

  /**
   * Verify a signature.
   *
   * @param signed The data that was signed.
   * @param signature The signature.
   * @return Result of verification
   * @throws KeyczarException If an Keyczar-specific error occurs 
   * @throws GeneralSecurityException If a Java JCE error occurs
   */
  public VerifyResult verify(final byte[] signed, final byte[] signature)
      throws KeyczarException, GeneralSecurityException  {
    ByteArrayInputStream input = new ByteArrayInputStream(signature);
    DataUnpacker unpacker = new DataUnpacker(input);
    int version = unpacker.getInt();
    if (version != Constants.getVersion()) {
      return VerifyResult.MALFORMED;
    }
    byte[] hash = unpacker.getArray();
    if (hash.length != Constants.getKeyHashSize()) {
      return VerifyResult.MALFORMED;
    }
    
    KeyczarKey key = getKey(hash);
    if (key == null) {
      return VerifyResult.KEY_UNAVAILABLE;
    }    
   
    byte[] rawSig = unpacker.getArray();
    if (rawSig.length != Constants.getDigestSize()) {
      return VerifyResult.MALFORMED;
    }
    VerifyingStream verifyingStream = (VerifyingStream) key.getStream();
    verifyingStream.initVerify();
    verifyingStream.updateVerify(signed, 0, signed.length);
    if (verifyingStream.verify(signature, 0, signature.length)) {
      return VerifyResult.VERIFIED;
    } else {
      return VerifyResult.FAILED;
    }
  }
}