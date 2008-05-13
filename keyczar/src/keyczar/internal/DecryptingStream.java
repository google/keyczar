package keyczar.internal;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

public interface DecryptingStream {
  VerifyingStream getVerifyingStream() throws KeyczarException;
  
  int maxOutputSize(int inputLen);

  void initDecrypt(ByteBuffer input) throws KeyczarException;
  
  int update(ByteBuffer input, ByteBuffer output) throws KeyczarException;

  int doFinal(ByteBuffer input, ByteBuffer output) throws KeyczarException;
}
