// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for DSA Public Keys. These must be exported from existing
 * DSA private key sets.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class DsaPublicKey extends KeyczarKey {
  private static final String SIG_ALGORITHM = "SHA1withDSA";
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private PublicKey publicKey;
  private int hashCode;
  
  @Expose private KeyType type;
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private String x509;

  void init() throws KeyczarException {
    hashCode = Util.toInt(hash);
    byte[] x509Bytes = Util.base64Decode(x509);
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      publicKey = kf.generatePublic(new X509EncodedKeySpec(x509Bytes));
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }
  
  protected void set(byte[] x509Bytes) throws KeyczarException {
    this.type = getType();
    this.x509 = Util.base64Encode(x509Bytes);
    byte[] fullHash = Util.prefixHash(x509Bytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    init();
  }

  @Override
  protected byte[] hash() {
    return hash;
  }  
  
  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  protected void generate() throws KeyczarException {
    throw new KeyczarException("Public DSA keys must be exported " +
        "from private keys");
  }

  @Override
  protected void read(String input) throws KeyczarException {
    DsaPublicKey copy = Util.gson().fromJson(input, DsaPublicKey.class);
    if (copy.type != this.getType()) {
     throw new KeyczarException("Incorrect type. Received: " + copy.type +
         " Expected: " + this.getType());
    }
    this.hash = copy.hash;
    this.x509 = copy.x509;
    byte[] fullHash = Util.prefixHash(Util.base64Decode(this.x509));
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Key hash does not match");
      }
    }
    init();
  }    
    
  @Override
  protected KeyType getType() {
    return KeyType.DSA_PUB;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new DsaVerifyingStream();
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  private class DsaVerifyingStream extends Stream implements VerifyingStream {
    private Signature signature;

    public int digestSize() {
      return getType().getOutputSize();
    }
    
    public DsaVerifyingStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify() throws KeyczarException {
      try {
        signature.initVerify(publicKey);
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
        return signature.verify(sig.array(), sig.position(),
            sig.limit() - sig.position());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }    
  }
}
