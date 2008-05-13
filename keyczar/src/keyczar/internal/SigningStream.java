package keyczar.internal;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

public interface SigningStream {
  int digestSize();
  
  void initSign() throws KeyczarException;
  
  void updateSign(ByteBuffer input);

  void sign(ByteBuffer output) throws KeyczarException;
}
