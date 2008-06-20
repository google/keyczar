package com.google.keyczar;

import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.enums.KeyStatus;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.KeyczarReader;
import com.google.keyczar.util.Util;

import java.util.HashMap;
import java.util.Map;

public class MockKeyczarReader extends KeyMetadata implements KeyczarReader {
  
  private Map<Integer, KeyczarKey> keys;
  
  public MockKeyczarReader(String n, KeyPurpose p, KeyType t) {
    super(n,p,t);
    keys = new HashMap<Integer, KeyczarKey>();
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    if (keys.containsKey(version)) {
      String s = keys.get(version).toString();
      System.out.println("DEBUG: " + s);
      return s;
    } else {
      throw new KeyczarException("Illegal version number.");
    }
  }

  @Override
  public String getMetadata() {
    return Util.gson().toJson(this);
  }
  
  public boolean addKey(int versionNumber, KeyStatus status) 
      throws KeyczarException {
    KeyczarKey key = KeyczarKey.genKey(getType());
    keys.put(versionNumber, key);
    return addVersion(new KeyVersion(versionNumber, status, false));
  }
  
  public boolean removeKey(int versionNumber) {
    return removeVersion(versionNumber);
  }
  
  public KeyStatus getStatus(int versionNumber) {
    return getVersion(versionNumber).getStatus();
  }
}