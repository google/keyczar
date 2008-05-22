package keyczar.interfaces;

import java.nio.ByteBuffer;

import keyczar.KeyczarException;

// TODO: Write JavaDocs
public interface SigningStream {
  // TODO: Write JavaDocs
  int digestSize();

  // TODO: Write JavaDocs
  void initSign() throws KeyczarException;

  // TODO: Write JavaDocs
  void sign(ByteBuffer output) throws KeyczarException;

  // TODO: Write JavaDocs
  void updateSign(ByteBuffer input) throws KeyczarException;
}
