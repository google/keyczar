package org.keyczar;


import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.BadVersionException;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Util;

import java.util.HashMap;
import java.util.Map;

/**
 * A mock representation of a KeyczarReader used for testing.
 *
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public class MockKeyczarReader implements KeyczarReader {

  private Map<Integer, KeyczarKey> keys, publicKeys; // link version #s to keys
  private KeyMetadata kmd, publicKmd;

  public MockKeyczarReader(String n, KeyPurpose p, KeyType t) {
    kmd = new KeyMetadata(n, p, t);
    publicKmd = null;
    keys = new HashMap<Integer, KeyczarKey>();
    publicKeys = new HashMap<Integer, KeyczarKey>();
  }

  public String getKey(int version) throws KeyczarException {
    if (keys.containsKey(version)) {
      return keys.get(version).toString();
    } else {
      throw new BadVersionException((byte) version);
    }
  }

  public String getMetadata() {
    return Util.gson().toJson(kmd);
  }

  public void setMetadata(KeyMetadata newKmd) {
    kmd = newKmd;
  }

  public void setPublicKeyMetadata(KeyMetadata publicKmd) {
    this.publicKmd = publicKmd;
  }

  public void setKey(int versionNumber, KeyczarKey key) {
    keys.put(versionNumber, key);
  }

  public void setPublicKey(int versionNumber, KeyczarKey key) {
    publicKeys.put(versionNumber, key);
  }

  public void removeKey(int versionNumber) {
    keys.remove(versionNumber);
  }

  public String name() {
    return kmd.getName();
  }

  public KeyPurpose purpose() {
    return kmd.getPurpose();
  }

  public KeyType type() {
    return kmd.getType();
  }

  public boolean addKey(int versionNumber, KeyStatus status)
      throws KeyczarException {
    KeyczarKey key = KeyczarKey.genKey(kmd.getType());
    keys.put(versionNumber, key);
    return kmd.addVersion(new KeyVersion(versionNumber, status, false));
  }

  public boolean addKey(int versionNumber, KeyStatus status, int size)
      throws KeyczarException {
    KeyczarKey key = KeyczarKey.genKey(kmd.getType(), size);
    keys.put(versionNumber, key);
    return kmd.addVersion(new KeyVersion(versionNumber, status, false));
  }

  public KeyStatus getStatus(int versionNumber) {
    return kmd.getVersion(versionNumber).getStatus();
  }

  public boolean existsVersion(int versionNumber) {
    return keys.containsKey(versionNumber);
  }

  public boolean exportedPublicKeySet() {
    return publicKmd != null;
  }

  public boolean hasPublicKey(int versionNumber) {
    KeyczarPrivateKey privateKey = (KeyczarPrivateKey) keys.get(versionNumber);
    KeyczarPublicKey publicKey =
      (KeyczarPublicKey) publicKeys.get(versionNumber);
    return privateKey != null && publicKey != null &&
      publicKey.equals(privateKey.getPublic());
  }

  public int numKeys() {
    return keys.size();
  }

  public int getKeySize(int versionNumber) {
    return keys.get(versionNumber).size();
  }
}