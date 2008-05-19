// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import keyczar.interfaces.PublicKeyExportable;
import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for DSA Private Keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class DsaPrivateKey extends KeyczarKey implements PublicKeyExportable {
  private static final String SIG_ALGORITHM = "SHA1withDSA";
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private PrivateKey privateKey;
  private int hashCode;
  
  @Expose private KeyType type = getType();
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private String pkcs8;
  @Expose private DsaPublicKey publicKey;
    
  private void init() throws KeyczarException {
    hashCode = Util.toInt(hash);
    byte[] pkcs8Bytes = Util.base64Decode(pkcs8);
    KeyFactory kf;
    try {
      kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
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
  public KeyczarKey getPublic() {
    return publicKey;
  }

  @Override
  protected void generate() throws KeyczarException {
    publicKey = new DsaPublicKey();
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM);
      kpg.initialize(getType().defaultSize());
      KeyPair pair = kpg.generateKeyPair();
      pkcs8 = Util.base64Encode(pair.getPrivate().getEncoded());
      publicKey.set(pair.getPublic().getEncoded());
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
    hash = publicKey.hash();
    init();
  }
  
  @Override
  protected void read(String input) throws KeyczarException {
    DsaPrivateKey copy = Util.gson().fromJson(input, DsaPrivateKey.class);
    if (copy.type != this.getType()) {
      throw new KeyczarException("Incorrect type. Received: " + copy.type +
          " Expected: " + this.getType());
     }
    this.hash = copy.hash;
    this.pkcs8 = copy.pkcs8;
    this.publicKey = copy.publicKey;
    this.publicKey.init();
    if (!Arrays.equals(this.hash, publicKey.hash())) {
        throw new KeyczarException("Key hash does not match");
    }
    init();
  }    
    
  @Override
  protected KeyType getType() {
    return KeyType.DSA_PRIV;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new DsaSigningStream();
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  private class DsaSigningStream extends Stream implements SigningStream,
      VerifyingStream {
    private Signature signature;
    private VerifyingStream verifyingStream;
    
    public int digestSize() {
      return getType().getOutputSize();
    }
    
    public DsaSigningStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        verifyingStream = (VerifyingStream) publicKey.getStream();
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initSign() throws KeyczarException {
      try {
        signature.initSign(privateKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
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
    public void initVerify() throws KeyczarException {
      verifyingStream.initVerify();
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
