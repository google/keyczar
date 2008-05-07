package keyczar;

import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;

abstract class KeyczarKey {
  protected KeyczarKey() {
    
  }
  
  static KeyczarKey fromType(KeyType type) throws KeyczarException {
    switch(type) {
      case AES:
      case HMAC_SHA1:
        return new KeyczarHmacKey();
    }
    
    throw new KeyczarException("Unsupported key type: " + type);
  }
  
  /**
   * Calculate a hash of the raw key material
   *
   * @return A hash of this key material
   */
  protected abstract byte[] hash();
  
  protected abstract KeyType getType();
 
  protected abstract void read(DataUnpacker unpacker) throws KeyczarException;
  
  protected abstract void generate() throws KeyczarException;
  
  protected abstract int write(DataPacker packer) throws KeyczarException;
}
