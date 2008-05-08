package keyczar.internal;

import java.security.GeneralSecurityException;

public interface SigningStream {
  void initSign() throws GeneralSecurityException;
  
  /**
   * Sign the given data
   *
   * @param data The data to sign
   * @param offset The offset to start at.
   * @param length The length of signed data.
   */
   void updateSign(byte[] data, int offset, int length);
  
  /**
   * Output a signature
   *
   * @param dest The destination where to write the signature
   * @param offset Signature start offset.
   */
  void sign(byte[] dest, int offset) throws GeneralSecurityException;
}
