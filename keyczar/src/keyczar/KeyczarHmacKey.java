// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.security.Key;

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
}
