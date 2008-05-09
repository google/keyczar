// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import keyczar.internal.*;

/**
 * Wrapping class for HMAC-SHA1 keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class KeyczarHmacKey extends KeyczarKey {
  private static final String MAC_ALGORITHM = "HMACSHA1";
  private Key hmacKey;
  private final byte[] hash = new byte[Constants.KEY_HASH_SIZE];
  private int hashCode;
    
  private void init(byte[] keyBytes) {
    byte[] fullHash = Util.hash(Util.fromInt(keyBytes.length), keyBytes);
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
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
  protected void read(DataUnpacker unpacker)
      throws KeyczarException {
    int typeValue = unpacker.getInt();
    if (typeValue != getType().getValue()) {
      throw new KeyczarException("Invalid key type for HMAC: " +
          KeyType.getType(typeValue));
    }
    byte[] keyMaterial = unpacker.getArray();
    init(keyMaterial);
  }

  @Override
  protected void generate() {
    init(Util.rand(getType().defaultSize()));
  }

  @Override
  protected int write(DataPacker packer) throws KeyczarException {
    if (hmacKey == null) {
      throw new KeyczarException("Cannot write uninitialized key");
    }
    int written = packer.putInt(getType().getValue());
    written += packer.putArray(hmacKey.getEncoded());
    return written;
  }

  @Override
  protected KeyType getType() {
    return KeyType.HMAC_SHA1;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new HmacStream(hmacKey);
  }

  private class HmacStream extends Stream implements VerifyingStream, SigningStream {
    private Mac hmac;

    public int digestSize() {
      return hmac.getMacLength();
    }
    
    public HmacStream(Key key) throws KeyczarException {
      try {
        this.hmac = Mac.getInstance(MAC_ALGORITHM);
        hmac.init(key);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify()  {
      hmac.reset();
    }

    @Override
    public void updateVerify(byte[] signedData, int offset, int length) {
      hmac.update(signedData, offset, length);
    }

    @Override
    public boolean verify(byte[] signature, int offset) {
      byte[] expectedSig = hmac.doFinal();
   
      if (expectedSig.length != (signature.length - offset)) {
        return false;
      }
      for (int i = 0; i < signature.length - offset; i++) {
        if (expectedSig[i] != signature[offset + i]) {
          return false;
        }
      }
      return true;
    }

    @Override
    public void initSign() {
      hmac.reset();
    }

    @Override
    public void sign(byte[] dest, int offset) throws KeyczarException {
      try {
        hmac.doFinal(dest, offset);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateSign(byte[] data, int offset, int length) {
      hmac.update(data, offset, length);
    }    
  }
}
