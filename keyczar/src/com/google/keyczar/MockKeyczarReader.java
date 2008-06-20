package com.google.keyczar;

import com.google.gson.annotations.Expose;
import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.KeyczarReader;
import com.google.keyczar.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class MockKeyczarReader extends KeyMetadata implements KeyczarReader {
  
  public MockKeyczarReader(String n, KeyPurpose p, KeyType t) {
    super(n,p,t);
  }
  
  public KeyVersion getVersion(int versionNumber) {
    return versionMap.get(versionNumber);
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    // TODO: implement me!
    throw new KeyczarException("Unimplemented!");
  }

  @Override
  public String getMetadata() throws KeyczarException {
    return Util.gson().toJson(this);
  }

}