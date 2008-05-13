package keyczar.internal;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

public interface VerifyingStream {
  int digestSize();
  
  void initVerify() throws KeyczarException;
  
  void updateVerify(ByteBuffer input);

  boolean verify(ByteBuffer signature);
}
