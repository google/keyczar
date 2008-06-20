package com.google.keyczar;

import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.KeyczarReader;
import com.google.keyczar.util.Util;

public class MockKeyczarReader extends KeyMetadata implements KeyczarReader {
  
  public MockKeyczarReader(String n, KeyPurpose p, KeyType t) {
    super(n,p,t);
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    throw new KeyczarException("Unimplemented!");
  }

  @Override
  public String getMetadata() {
    return Util.gson().toJson(this);
  }
}