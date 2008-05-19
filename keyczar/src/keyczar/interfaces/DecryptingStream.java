package keyczar.interfaces;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

// TODO: Write JavaDocs
public interface DecryptingStream {
  // TODO: Write JavaDocs
  VerifyingStream getVerifyingStream() throws KeyczarException;
  
  // TODO: Write JavaDocs
  int maxOutputSize(int inputLen);

  // TODO: Write JavaDocs
  void initDecrypt(ByteBuffer input) throws KeyczarException;
  
  // TODO: Write JavaDocs
  int update(ByteBuffer input, ByteBuffer output) throws KeyczarException;

  // TODO: Write JavaDocs
  int doFinal(ByteBuffer input, ByteBuffer output) throws KeyczarException;
}
