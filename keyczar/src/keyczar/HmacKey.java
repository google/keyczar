// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
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
public class HmacKey extends KeyczarKey {
  private static final String MAC_ALGORITHM = "HMACSHA1";
  private Key hmacKey;
  private final byte[] hash = new byte[Constants.KEY_HASH_SIZE];
  private int hashCode;
  private String stringRep;
    
  private void init(byte[] keyBytes) throws KeyczarException {
    byte[] fullHash = Util.hash(Util.fromInt(keyBytes.length), keyBytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
    hashCode = Util.toInt(hash);
    this.hmacKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
    
    try {
      JSONObject json = new JSONObject();
      json.put("type", getType().getValue());
      json.put("hmackey", Util.base64Encode(keyBytes));
      stringRep = json.toString();
    } catch (JSONException e) {
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
    init(Util.rand(getType().defaultSize()));
  }

  @Override
  protected void read(String input) throws KeyczarException {
    try {
      JSONObject json = new JSONObject(input);
      int typeValue = json.getInt("type");
      if (typeValue != getType().getValue()) {
        throw new KeyczarException("Invalid key type for HMAC: " +
            KeyType.getType(typeValue));
      }
      byte[] keyMaterial = Util.base64Decode(json.getString("hmackey"));      
      init(keyMaterial);
    } catch (JSONException e) {
      throw new KeyczarException(e);
    } catch (IOException e) {
      throw new KeyczarException(e);
    }
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
    return stringRep;
  }

  private class HmacStream extends Stream implements VerifyingStream, SigningStream {
    private Mac hmac;

    public int digestSize() {
      return hmac.getMacLength();
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
