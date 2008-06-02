package com.google.keyczar.interfaces;

import com.google.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;


public interface VerifyingStream extends Stream {
  // TODO: Write JavaDocs
  int digestSize();

  // TODO: Write JavaDocs
  void initVerify() throws KeyczarException;

  // TODO: Write JavaDocs
  void updateVerify(ByteBuffer input) throws KeyczarException;

  // TODO: Write JavaDocs
  boolean verify(ByteBuffer signature) throws KeyczarException;
}
