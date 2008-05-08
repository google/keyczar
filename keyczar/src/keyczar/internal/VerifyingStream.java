package keyczar.internal;

import java.security.GeneralSecurityException;

public interface VerifyingStream {
  void initVerify() throws GeneralSecurityException;
  
  /**
   * Update with some signed data
   *
   * @param signedData The signed data to verify
   * @param offset The offset to start at.
   * @param length The length of signed data.
   */
   void updateVerify(byte[] signedData, int offset, int length);
  
  /**
   * Verify a signature.
   *
   * @param signature The signature
   * @param offset Signature start offset.
   * @param length Signature length.
   *
   * @return Success of verification.
   */
  boolean verify(byte[] signature, int offset, int length);
}
