// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for HMAC-SHA1 keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class HmacKey extends KeyczarKey {
  private static final String MAC_ALGORITHM = "HMACSHA1";
  private Key hmacKey;
  @Expose private KeyType type = getType();
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  private int hashCode;
  @Expose private String hmacKeyString;
  private String stringRep;  
  
  void init() throws KeyczarException {
    byte[] keyBytes = Util.base64Decode(hmacKeyString);
    hashCode = Util.toInt(hash);
    this.hmacKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
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
    byte[] keyBytes = Util.rand(getType().defaultSize() / 8);
    this.type = getType();
    hmacKeyString = Util.base64Encode(keyBytes);
    byte[] fullHash = Util.prefixHash(keyBytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    init();
  }

  @Override
  protected void read(String input) throws KeyczarException {
    HmacKey copy = Util.gson().fromJson(input, HmacKey.class);
    if (copy.type != getType()) {
      throw new KeyczarException("Invalid type in input: " + copy.type);
    }
    this.type = copy.type;
    this.hmacKeyString = copy.hmacKeyString;
    this.hash = copy.hash;
    byte[] hmacBytes = Util.base64Decode(hmacKeyString);
    byte[] fullHash = Util.prefixHash(hmacBytes);
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Hash does not match");
      }
    }
    init();
  }

  @Override
  protected KeyType getType() {
    return KeyType.HMAC_SHA1;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new HmacStream();
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  private class HmacStream extends Stream implements
      VerifyingStream, SigningStream {
    private Mac hmac;

    public int digestSize() {
      return getType().getOutputSize();
    }
    
    public HmacStream() throws KeyczarException {
      try {
        this.hmac = Mac.getInstance(MAC_ALGORITHM);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify() throws KeyczarException {
      initSign();
    }

    @Override
    public void updateVerify(ByteBuffer input) {
      updateSign(input);      
    }

    @Override
    public boolean verify(ByteBuffer signature) {
      byte[] sigBytes = new byte[digestSize()];
      signature.get(sigBytes);
      
      return Arrays.equals(hmac.doFinal(), sigBytes);
    }

    @Override
    public void initSign() throws KeyczarException {
      try {
        hmac.init(hmacKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void sign(ByteBuffer output) {
      output.put(hmac.doFinal());
    }

    @Override
    public void updateSign(ByteBuffer input) {
      hmac.update(input);
    }    
  }
}
