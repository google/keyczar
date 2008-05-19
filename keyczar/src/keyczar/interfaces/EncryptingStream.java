package keyczar.interfaces;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

// TODO: Write JavaDocs
public interface EncryptingStream {
  
  // TODO: Write JavaDocs
  SigningStream getSigningStream() throws KeyczarException;
  
  // TODO: Write JavaDocs
  byte[] initEncrypt() throws KeyczarException;
  
  // TODO: Write JavaDocs
  int maxOutputSize(int inputLen);

  // TODO: Write JavaDocs
  int ivSize();
  
  // TODO: Write JavaDocs
  int update(ByteBuffer input, ByteBuffer output) throws KeyczarException;

  // TODO: Write JavaDocs
  int doFinal(ByteBuffer input, ByteBuffer output) throws KeyczarException;
}
