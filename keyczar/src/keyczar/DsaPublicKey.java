// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;

import keyczar.enums.KeyType;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for DSA Public Keys. These must be exported from existing DSA
 * private key sets.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 * 
 */
class DsaPublicKey extends KeyczarPublicKey {
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private static final String SIG_ALGORITHM = "SHA1withDSA";

  @Override
  public Stream getStream() throws KeyczarException {
    return new DsaVerifyingStream();
  }

  @Override
  String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  @Override
  KeyType getType() {
    return KeyType.DSA_PUB;
  }

  private class DsaVerifyingStream extends Stream implements VerifyingStream {
    private Signature signature;

    public DsaVerifyingStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
    }

    @Override
    public void initVerify() throws KeyczarException {
      try {
        signature.initVerify(getJcePublicKey());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateVerify(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public boolean verify(ByteBuffer sig) throws KeyczarException {
      try {
        return signature.verify(sig.array(), sig.position(), sig.limit()
            - sig.position());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
  }
}
