// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import keyczar.interfaces.EncryptingStream;
import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for RSA Public Keys. These must be exported from existing
 * RSA private key sets.
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class RsaPublicKey extends KeyczarKey {
  private static final String SIG_ALGORITHM = "SHA1withRSA";
  private static final String CRYPT_ALGORITHM =
    "RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING";
  private static final String KEY_GEN_ALGORITHM = "RSA";
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
    throw new KeyczarException("Public RSA keys must be exported " +
        "from private keys");
  }

  @Override
  protected void read(String input) throws KeyczarException {
    RsaPublicKey copy = Util.gson().fromJson(input, RsaPublicKey.class);
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
    return KeyType.RSA_PUB;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new RsaStream();
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  private class RsaStream extends Stream implements VerifyingStream,
      EncryptingStream {
    private Signature signature;
    private Cipher cipher;

    public int digestSize() {
      return getType().getOutputSize();
    }
    
    public RsaStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        cipher = Cipher.getInstance(CRYPT_ALGORITHM);
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

    @Override
    public SigningStream getSigningStream() {
      return new SigningStream() {
        @Override
        public int digestSize() {
          return 0;
        }

        @Override
        public void initSign() {
          // Do nothing
        }

        @Override
        public void sign(ByteBuffer output) {
          // Do nothing
        }

        @Override
        public void updateSign(ByteBuffer input) {
          // Do nothing
        }
      };
    }

    @Override
    public byte[] initEncrypt() throws KeyczarException {
      try {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      } catch (InvalidKeyException e) {
        throw new KeyczarException(e);
      }
      return new byte[0];
    }

    @Override
    public int ivSize() {
      return 0;
    }

    @Override
    public int maxOutputSize(int inputLen) {
      return getType().getOutputSize();
    }

    @Override
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (ShortBufferException e) {
        throw new KeyczarException(e);
      }
    }
    
    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
  }
}
