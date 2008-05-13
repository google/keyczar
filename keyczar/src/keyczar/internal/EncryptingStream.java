package keyczar.internal;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

public interface EncryptingStream {
  
  SigningStream getSigningStream() throws KeyczarException;
  
  byte[] initEncrypt() throws KeyczarException;
  
  int maxOutputSize(int inputLen);

  int ivSize();
  
  int update(ByteBuffer input, ByteBuffer output) throws KeyczarException;

  int doFinal(ByteBuffer input, ByteBuffer output) throws KeyczarException;
}
