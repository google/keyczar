package keyczar.interfaces;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

public interface VerifyingStream {
  // TODO: Write JavaDocs
  int digestSize();

  // TODO: Write JavaDocs
  void initVerify() throws KeyczarException;

  // TODO: Write JavaDocs
  void updateVerify(ByteBuffer input) throws KeyczarException;

  // TODO: Write JavaDocs
  boolean verify(ByteBuffer signature) throws KeyczarException;
}
