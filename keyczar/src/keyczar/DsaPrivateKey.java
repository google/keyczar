// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import keyczar.internal.Constants;
import keyczar.internal.SigningStream;
import keyczar.internal.Util;
import keyczar.internal.VerifyingStream;

/**
 * Wrapping class for HMAC-SHA1 keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class DsaPrivateKey extends KeyczarKey {
  private static final String SIG_ALGORITHM = "SHA1withDSA";
  private static final String KEY_GEN_ALGORITHM = "DSA";
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private int hashCode;
  
  @Expose private KeyType type;
  @Expose private byte[] hash = new byte[Constants.KEY_HASH_SIZE];
  @Expose private String x;
  @Expose private String y;
  @Expose private String p;
  @Expose private String q;
  @Expose private String g;
    
  private void init() throws KeyczarException {
    hashCode = Util.toInt(hash);
    BigInteger xInt = new BigInteger(Util.base64Decode(x));
    BigInteger yInt = new BigInteger(Util.base64Decode(y));
    BigInteger pInt = new BigInteger(Util.base64Decode(p));
    BigInteger qInt = new BigInteger(Util.base64Decode(q));
    BigInteger gInt = new BigInteger(Util.base64Decode(g));
    try {
      KeyFactory kf = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      privateKey =
        kf.generatePrivate(new DSAPrivateKeySpec(xInt, pInt, qInt, gInt));
      publicKey =
        kf.generatePublic(new DSAPublicKeySpec(yInt, pInt, qInt, gInt));
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
  protected void generate() throws KeyczarException {
    DSAPrivateKey priv;
    DSAPublicKey pub;

    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM);
      kpg.initialize(getType().defaultSize());
      KeyPair pair = kpg.generateKeyPair();
      priv = (DSAPrivateKey) pair.getPrivate();
      pub = (DSAPublicKey) pair.getPublic();
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }

    x = Util.base64Encode(priv.getX().toByteArray());
    y = Util.base64Encode(pub.getY().toByteArray());
    p = Util.base64Encode(pub.getParams().getP().toByteArray());
    q = Util.base64Encode(pub.getParams().getQ().toByteArray());
    g = Util.base64Encode(pub.getParams().getG().toByteArray());
    System.arraycopy(fullHash(), 0, hash, 0, hash.length);
    init();
  }
  
  private byte[] fullHash() throws KeyczarException {
    byte[] xBytes = Util.base64Decode(x);
    byte[] yBytes = Util.base64Decode(y);
    byte[] pBytes = Util.base64Decode(p);
    byte[] qBytes = Util.base64Decode(q);
    byte[] gBytes = Util.base64Decode(g);
    return Util.prefixHash(xBytes, yBytes, pBytes, qBytes, gBytes);
  }

  @Override
  protected void read(String input) throws KeyczarException {
    DsaPrivateKey copy = Util.gson().fromJson(input, DsaPrivateKey.class);
    this.x = copy.x;
    this.y = copy.y;
    this.p = copy.p;
    this.q = copy.q;
    this.g = copy.g;
    this.hash = copy.hash;
    byte[] fullHash = fullHash();
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Key hash does not match");
      }
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

  private class DsaSigningStream extends Stream implements SigningStream, VerifyingStream {
    private Signature signature;

    public int digestSize() {
      return getType().getOutputSize();
    }
    
    public DsaSigningStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
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
