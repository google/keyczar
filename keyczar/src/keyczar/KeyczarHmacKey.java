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
  private byte[] hash;
    
  private void init(byte[] keyBytes) throws DataPackingException {
    this.hash = Util.hashPacked(keyBytes);
    this.hmacKey = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
  }
  
  /* (non-Javadoc)
   * @see keyczar.KeyczarKey#hash()
   */
  @Override
  protected byte[] hash() {
    return hash;
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
  protected void generate() throws KeyczarException {
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

  class HmacStream extends Stream implements VerifyingStream, SigningStream {
    private Mac hmac;
    private Key key;

    public HmacStream(Key key) throws GeneralSecurityException {
      this.hmac = Mac.getInstance(MAC_ALGORITHM);
      this.key = key;
    }

    @Override
    public void initVerify() throws GeneralSecurityException {
      initSign();
    }

    @Override
    public void updateVerify(byte[] signedData, int offset, int length) {
      updateSign(signedData, offset, length);
    }

    @Override
    public boolean verify(byte[] signature, int offset, int length) {
      byte[] sig = hmac.doFinal();
      for (int i = 0; i < length; i++) {
        if (sig[i] != signature[offset + i]) {
          return false;
        }
      }
      return true;
    }

    @Override
    public void initSign() throws GeneralSecurityException {
      hmac.init(key);
    }

    @Override
    public void sign(byte[] dest, int offset) throws GeneralSecurityException {
      hmac.doFinal(dest, offset);
    }

    @Override
    public void updateSign(byte[] data, int offset, int length) {
      hmac.update(data, offset, length);
    }    
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    try {
      Stream hmacStream = new HmacStream(hmacKey);
      return hmacStream;
    } catch (GeneralSecurityException e) {
      throw new KeyczarException("Unable to initialize stream", e);
    }
  }
}
