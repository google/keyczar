// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import keyczar.interfaces.DecryptingStream;
import keyczar.interfaces.EncryptingStream;
import keyczar.interfaces.PublicKeyExportable;
import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for RSA Private Keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class RsaPrivateKey extends KeyczarKey implements PublicKeyExportable {
  private static final String SIG_ALGORITHM = "SHA1withRSA";
  private static final String CRYPT_ALGORITHM =
    "RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING";
  private static final String KEY_GEN_ALGORITHM = "RSA";
  private PrivateKey privateKey;
  private int hashCode;
  
  @Expose private KeyType type = getType();
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private String pkcs8;
  @Expose private RsaPublicKey publicKey;
    
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
    publicKey = new RsaPublicKey();
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
    RsaPrivateKey copy = Util.gson().fromJson(input, RsaPrivateKey.class);
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
    return KeyType.RSA_PRIV;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new RsaPrivateStream();
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  private class RsaPrivateStream extends Stream implements SigningStream,
      VerifyingStream, DecryptingStream, EncryptingStream {
    private Signature signature;
    private Cipher cipher;
    private EncryptingStream encryptingStream;
    private VerifyingStream verifyingStream;

    public int digestSize() {
      return getType().getOutputSize();
    }
    
    public RsaPrivateStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        verifyingStream = (VerifyingStream) publicKey.getStream();
        cipher = Cipher.getInstance(CRYPT_ALGORITHM);
        encryptingStream = (EncryptingStream) publicKey.getStream();
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

    @Override
    public VerifyingStream getVerifyingStream() {
      return new VerifyingStream() {
        @Override
        public int digestSize() {
          return 0;
        }

        @Override
        public void initVerify() {
          // Do nothing
        }

        @Override
        public void updateVerify(ByteBuffer input) {
          // Do nothing
        }

        @Override
        public boolean verify(ByteBuffer signature) {
          // Do nothing
          return true;
        }
      };
    }

    @Override
    public void initDecrypt(ByteBuffer input) throws KeyczarException {
      try {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
      } catch (InvalidKeyException e) {
       throw new KeyczarException(e);
      }
    }
    
    @Override
    public int updateDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (ShortBufferException e) {
        throw new KeyczarException(e);
      }
    }
    
    @Override
    public int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int maxOutputSize(int inputLen) {
      // TODO Auto-generated method stub
      return getType().getOutputSize() * 2;
    }

    @Override
    public SigningStream getSigningStream() throws KeyczarException {
      return encryptingStream.getSigningStream();
    }

    @Override
    public byte[] initEncrypt() throws KeyczarException {
      return encryptingStream.initEncrypt();
    }

    @Override
    public int ivSize() {
      return 0;
    }

    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return encryptingStream.doFinalEncrypt(input, output);
    }

    @Override
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return encryptingStream.updateEncrypt(input, output);
    }    
  }
}
