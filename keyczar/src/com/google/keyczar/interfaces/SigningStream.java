package com.google.keyczar.interfaces;

import com.google.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;


// TODO: Write JavaDocs
public interface SigningStream extends Stream {
  // TODO: Write JavaDocs
  int digestSize();

  // TODO: Write JavaDocs
  void initSign() throws KeyczarException;

  // TODO: Write JavaDocs
  void sign(ByteBuffer output) throws KeyczarException;

  // TODO: Write JavaDocs
  void updateSign(ByteBuffer input) throws KeyczarException;
}
