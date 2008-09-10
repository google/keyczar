package org.keyczar;

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;

/**
 * Wrapper class to access Keyczar utility methods of reading and manipulating
 * key metadata files. Also contains additional utility methods for pushing
 * updates to meta files on disk and exporting public key sets.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
class GenericKeyczar extends Keyczar {
  GenericKeyczar(KeyczarReader reader) throws KeyczarException {
    super(reader);
  }

  GenericKeyczar(String location) throws KeyczarException {
    super(location);
  }

  @Override
  boolean isAcceptablePurpose(KeyPurpose purpose) {
    return true;
  }

  KeyMetadata getMetadata() {
    return this.kmd;
  }

  Set<KeyVersion> getVersions() {
    return Collections.unmodifiableSet(versionMap.keySet());
  }

  KeyczarKey getKey(KeyVersion v) {
    return versionMap.get(v);
  }

  /**
   * Promotes the status of key with given version number. Promoting ACTIVE key
   * automatically demotes current PRIMARY key to ACTIVE.
   *
   * @param versionNumber integer version number to promote
   * @throws KeyczarException if invalid version number or trying to promote
   * a primary key.
   */
  void promote(int versionNumber) throws KeyczarException {
    KeyVersion version = getVersion(versionNumber);
    KEYCZAR_LOGGER.info(Messages.getString("Keyczar.PromotedVersion", version));
    switch (version.getStatus()) {
      case PRIMARY:
        throw new KeyczarException(
            Messages.getString("Keyczar.CantPromotePrimary"));
      case ACTIVE:
        version.setStatus(KeyStatus.PRIMARY); // promote to PRIMARY
        if (primaryVersion != null) {
          primaryVersion.setStatus(KeyStatus.ACTIVE); // only one PRIMARY key
        }
        primaryVersion = version;
        break;
      case INACTIVE:
        version.setStatus(KeyStatus.ACTIVE);
        break;
    }
  }

  /**
   * Demotes the status of key with given version number. Demoting PRIMARY key
   * results in a key set with no primary version.
   *
   * @param versionNumber integer version number to demote
   * @throws KeyczarException if invalid version number or trying to demote
   * a key scheduled for revocation.
   */
  void demote(int versionNumber) throws KeyczarException {
    KeyVersion version = getVersion(versionNumber);
    KEYCZAR_LOGGER.info(Messages.getString("Keyczar.DemotingVersion", version));
    switch (version.getStatus()) {
      case PRIMARY:
        version.setStatus(KeyStatus.ACTIVE);
        primaryVersion = null; // no more PRIMARY keys in the set
        break;
      case ACTIVE:
        version.setStatus(KeyStatus.INACTIVE);
        break;
      case INACTIVE:
        throw new KeyczarException(
            Messages.getString("Keyczar.CantDemoteScheduled"));
    }
  }


  /**
   * Uses default key size to add a new key version.
   *
   * @param status KeyStatus desired for new key version
   */
  void addVersion(KeyStatus status) throws KeyczarException {
    addVersion(status, kmd.getType().defaultSize());
  }

  /**
   * Adds a new key version with given status and next available version
   * number to key set. Generates a new key of same type (repeated until hash
   * identifier is unique) for this version. Uses supplied key size in lieu
   * of the default key size. If this is an unacceptable key size, defaults
   * to the default key size.
   *
   * @param status KeyStatus desired for new key version
   * @param keySize desired key size in bits
   * @throws KeyczarException if key type is unsupported.
   */
  void addVersion(KeyStatus status, int keySize) throws KeyczarException {
    KeyVersion version = new KeyVersion(numVersions() + 1, status, false);
    if (status == KeyStatus.PRIMARY) {
      if (primaryVersion != null) {
        primaryVersion.setStatus(KeyStatus.ACTIVE);
      }
      primaryVersion = version;
    }
    KeyczarKey key;
    if (keySize < kmd.getType().defaultSize()) { // print a warning statement
      KEYCZAR_LOGGER.warn(Messages.getString("Keyczar.SizeWarning",
          keySize, kmd.getType().defaultSize(), kmd.getType().toString()));
    }
    do { // Make sure no keys collide on their identifiers
      key = KeyczarKey.genKey(kmd.getType(), keySize);
    } while (getKey(key.hash()) != null);
    addKey(version, key);
    KEYCZAR_LOGGER.info(Messages.getString("Keyczar.NewVersion", version));
  }


  int numVersions() {
    return versionMap.size();
  }

  /**
   * Returns the version corresponding to the version number if it exists.
   *
   * @param versionNumber
   * @return KeyVersion if it exists
   * @throws KeyczarException if version number doesn't exist
   */
   KeyVersion getVersion(int versionNumber) throws KeyczarException {
    KeyVersion version = kmd.getVersion(versionNumber);
    if (version == null) {
      throw new KeyczarException(
          Messages.getString("Keyczar.NoSuchVersion", versionNumber));
    }
    return version;
  }


  /**
   * Revokes the key with given version number if it is scheduled to be revoked.
   *
   * @param versionNumber integer version number to be revoked
   * @throws KeyczarException if version number nonexistent or key is not
   * scheduled for revocation.
   */
  void revoke(int versionNumber) throws KeyczarException {
    KeyVersion version = getVersion(versionNumber);
    if (version.getStatus() == KeyStatus.INACTIVE) {
      kmd.removeVersion(versionNumber);
    } else {
      throw new KeyczarException(Messages.getString("Keyczar.CantRevoke"));
    }
  }

  /**
   * For the managed key set, exports a set of public keys at given location.
   * Client's key must be a private key for DSA or RSA. For DSA private key,
   * purpose must be SIGN_AND_VERIFY. For RSA private key, purpose can also
   * be DECRYPT_AND_ENCRYPT.KeyczarTool
   *
   * @param destination String pathname of directory to export key set to
   * @throws KeyczarException if unable to export key set.
   */
  void publicKeyExport(String destination) throws KeyczarException {
    KeyMetadata kmd = getMetadata();
    // Can only export if type is DSA_PRIV and purpose is SIGN_AND_VERIFY
    KeyMetadata publicKmd = null;
    switch(kmd.getType()) {
      case DSA_PRIV: // DSA Private Key
        if (kmd.getPurpose() == KeyPurpose.SIGN_AND_VERIFY) {
          publicKmd = new KeyMetadata(kmd.getName(), KeyPurpose.VERIFY,
              KeyType.DSA_PUB);
        }
        break;
      case RSA_PRIV: // RSA Private Key
        switch(kmd.getPurpose()) {
          case DECRYPT_AND_ENCRYPT:
            publicKmd = new KeyMetadata(kmd.getName(), KeyPurpose.ENCRYPT,
                KeyType.RSA_PUB);
            break;
          case SIGN_AND_VERIFY:
            publicKmd = new KeyMetadata(kmd.getName(), KeyPurpose.VERIFY,
                KeyType.RSA_PUB);
            break;
        }
        break;
    }
    if (publicKmd == null) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.CannotExportPubKey",
              kmd.getType(), kmd.getPurpose()));
    }

    for (KeyVersion version : getVersions()) {
      KeyczarKey publicKey =
        ((KeyczarPrivateKey) getKey(version)).getPublic();
      if (KeyczarTool.getMock() == null) {
        writeFile(publicKey.toString(), destination
            + version.getVersionNumber());
      } else { // for testing, update mock object
        KeyczarTool.getMock().setPublicKey(version.getVersionNumber(), publicKey);
      }
      publicKmd.addVersion(version);
    }
    if (KeyczarTool.getMock() == null) {
      writeFile(publicKmd.toString(), destination
          + KeyczarFileReader.META_FILE);
    } else { // for testing, update mock public kmd
      KeyczarTool.getMock().setPublicKeyMetadata(publicKmd);
    }
  }

  /**
   * Pushes updated KeyMetadata and KeyVersion info to files at given
   * directory location. Version files are named by their number and the
   * meta file is named meta.
   *
   * @param location String pathname of directory to write to
   * @throws KeyczarException if unable to write to given location.
   */
  void write(String location) throws KeyczarException {
    writeFile(kmd.toString(), location
        + KeyczarFileReader.META_FILE);
    for (KeyVersion version : getVersions()) {
      writeFile(getKey(version).toString(), location
          + version.getVersionNumber());
    }
  }

  /**
   * Encrypts the key files before writing them out to disk
   *
   * @param location Location of key set
   * @param encrypter The encrypter object used to encrypt keys
   * @throws KeyczarException If unable to write to a given location
   */
  void writeEncrypted(String location, Encrypter encrypter)
      throws KeyczarException {
    KeyMetadata kmd = getMetadata();
    kmd.setEncrypted(true);
    writeFile(kmd.toString(), location + KeyczarFileReader.META_FILE);
    for (KeyVersion version : getVersions()) {
      writeFile(encrypter.encrypt(getKey(version).toString()), location
          + version.getVersionNumber());
    }
  }

  /**
   * Utility function to write given data to a file at given location.
   *
   * @param data String data to be written
   * @param location String pathname of destination file
   * @throws KeyczarException if unable to write to file.
   */
  void writeFile(String data, String location)
      throws KeyczarException {
    File outputFile = new File(location);
    try {
      FileWriter writer = new FileWriter(outputFile);
      writer.write(data);
      writer.close();
    } catch (IOException e) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.UnableToWrite",
              outputFile.toString()), e);
    }
  }
}
