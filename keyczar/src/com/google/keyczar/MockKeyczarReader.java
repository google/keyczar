package com.google.keyczar;

import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.KeyczarReader;

public class MockKeyczarReader implements KeyczarReader {

  @Override
  public String getKey(int version) throws KeyczarException {
    // TODO: implement me!
    throw new KeyczarException("Unimplemented!");
  }

  @Override
  public String getMetadata() throws KeyczarException {
    // TODO: implement me!
    throw new KeyczarException("Unimplemented!");
  }

}