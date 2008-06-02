package com.google.keyczar.interfaces;

import com.google.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;


// TODO: Write JavaDocs
public interface DecryptingStream extends Stream {
  // TODO: Write JavaDocs
  int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;

  // TODO: Write JavaDocs
  VerifyingStream getVerifyingStream() throws KeyczarException;

  // TODO: Write JavaDocs
  void initDecrypt(ByteBuffer input) throws KeyczarException;

  // TODO: Write JavaDocs
  int maxOutputSize(int inputLen);

  // TODO: Write JavaDocs
  int updateDecrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;
}
