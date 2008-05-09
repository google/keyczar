package keyczar;

import java.io.ByteArrayOutputStream;

import keyczar.internal.Constants;
import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;
import keyczar.internal.Util;

abstract class KeyczarKey {
  static KeyczarKey fromType(KeyType type) throws KeyczarException {
    switch(type) {
      case AES:
      case HMAC_SHA1:
        return new KeyczarHmacKey();
    }
    
    throw new KeyczarException("Unsupported key type: " + type);
  }
  
  /**
   * Return this key's hash value
   *
   * @return A hash of this key material
   */
  protected abstract byte[] hash();

  protected abstract KeyType getType();
 
  protected abstract void read(DataUnpacker unpacker) throws KeyczarException;
  
  protected abstract void generate();
  
  protected abstract int write(DataPacker packer) throws KeyczarException;
  
  protected abstract Stream getStream() throws KeyczarException;
  
  protected abstract static class Stream {
  }
}
