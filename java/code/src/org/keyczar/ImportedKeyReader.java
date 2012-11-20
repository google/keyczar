package org.keyczar;

import org.keyczar.annotations.Experimental;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;

import java.util.ArrayList;
import java.util.List;

@Experimental
public class ImportedKeyReader implements KeyczarReader {
  private final KeyMetadata metadata;
  private final List<KeyczarKey> keys;

  ImportedKeyReader(KeyMetadata metadata, List<KeyczarKey> keys) {
    this.metadata = metadata;
    this.keys = keys;
  }

  ImportedKeyReader(AesKey key) {
    this.metadata = new KeyMetadata(
            "Imported AES", KeyPurpose.DECRYPT_AND_ENCRYPT, DefaultKeyType.AES);
    KeyVersion version = new KeyVersion(0, KeyStatus.PRIMARY, false);
    this.metadata.addVersion(version);
    this.keys = new ArrayList<KeyczarKey>();
    this.keys.add(key);
  }

  ImportedKeyReader(HmacKey key) {
    this.metadata = new KeyMetadata(
            "Imported HMAC", KeyPurpose.SIGN_AND_VERIFY, DefaultKeyType.HMAC_SHA1);
    KeyVersion version = new KeyVersion(0, KeyStatus.PRIMARY, false);
    this.metadata.addVersion(version);
    this.keys = new ArrayList<KeyczarKey>();
    this.keys.add(key);
  }

  @Override
  public String getKey() throws KeyczarException {
	KeyMetadata metadata = KeyMetadata.read(getMetadata());
		
	return getKey(metadata.getPrimaryVersion().getVersionNumber());
  }

  @Override
  public String getKey(int version) {
    return keys.get(version).toString();
  }

  @Override
  public String getMetadata() {
    return metadata.toString();
  }
}
