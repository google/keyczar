package com.google.keyczar.interfaces;

import com.google.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;


// TODO: Write JavaDocs
public interface EncryptingStream extends Stream {

  // TODO: Write JavaDocs
  int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;

  // TODO: Write JavaDocs
  SigningStream getSigningStream() throws KeyczarException;

  // TODO: Write JavaDocs
  int initEncrypt(ByteBuffer output) throws KeyczarException;

  // TODO: Write JavaDocs
  int maxOutputSize(int inputLen);

  // TODO: Write JavaDocs
  int updateEncrypt(ByteBuffer input, ByteBuffer output)
      throws KeyczarException;
}
