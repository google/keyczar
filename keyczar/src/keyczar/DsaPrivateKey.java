// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.SignatureException;

import keyczar.enums.KeyType;
import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for DSA Private Keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 * 
 */
class DsaPrivateKey extends KeyczarPrivateKey {
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private static final String SIG_ALGORITHM = "SHA1withDSA";

  @Expose private DsaPublicKey publicKey;
  
  DsaPrivateKey() {
    publicKey = new DsaPublicKey();
  }

  @Override
  String getKeyGenAlgorithm() {
    return KEY_GEN_ALGORITHM;
  }

  @Override
  KeyczarPublicKey getPublic() {
    return publicKey;
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new DsaSigningStream();
  }

  @Override
  KeyType getType() {
    return KeyType.DSA_PRIV;
  }

  @Override
  void setPublic(KeyczarPublicKey pub) throws KeyczarException {
    publicKey = (DsaPublicKey) pub;
    publicKey.init();
  }

  private class DsaSigningStream extends Stream implements SigningStream,
      VerifyingStream {
    private Signature signature;
    private VerifyingStream verifyingStream;

    public DsaSigningStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        verifyingStream = (VerifyingStream) publicKey.getStream();
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    public int digestSize() {
      return getType().getOutputSize();
    }

    @Override
    public void initSign() throws KeyczarException {
      try {
        signature.initSign(getJcePrivateKey());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify() throws KeyczarException {
      verifyingStream.initVerify();
    }

    @Override
    public void sign(ByteBuffer output) throws KeyczarException {
      try {
        byte[] sig = signature.sign();
        output.put(sig);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateSign(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateVerify(ByteBuffer input) throws KeyczarException {
      verifyingStream.updateVerify(input);
    }

    @Override
    public boolean verify(ByteBuffer sig) throws KeyczarException {
      return verifyingStream.verify(sig);
    }
  }
}
