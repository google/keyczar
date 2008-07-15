/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keyczar;


import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


/**
 * Command line tool for generating Keyczar key files. The following commands
 * are supported:
 * <ul>
 *   <li>create: create a new key store
 *   <li>addkey: add new key to existing store
 *   <li>pubkey: export a public key set from existing private key store
 *   <li>promote: promote status of a key version in existing store
 *   <li>demote: demote status of a key version in existing store
 *   <li>revoke: revoke key version in existing store (if scheduled to be)
 * </ul>
 * 
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 * 
 */

public class KeyczarTool {
  static String asymmetricFlag;
  static String destinationFlag;
  static String locationFlag;
  static String crypterFlag;
  static String nameFlag;
  static int versionFlag = -1; // default if not set
  static int sizeFlag = -1; // default if not set
  static KeyPurpose purposeFlag;
  static KeyStatus statusFlag = KeyStatus.ACTIVE; // default if not set
  static MockKeyczarReader mock = null;
  
  /**
   * Sets the mock KeyczarReader used only for testing.
   * 
   * @param reader
   */
  public static void setReader(MockKeyczarReader reader) {
    mock = reader;
  }

  /**
   * Uses setFlags() to parse command line arguments and delegates to the
   * appropriate command function or prints the usage instructions if command
   * syntax is invalid.
   * 
   * @param args from the command line
   * @throws KeyczarException for illegal commands.
   */
  public static void main(String[] args) throws KeyczarException {
    if (args.length == 0) {
      printUsage();
    } else {
      setFlags(args);
      if (args[0].equals(Messages.getString("KeyczarTool.Create"))) {
        create();
      } else if (args[0].equals(Messages.getString("KeyczarTool.Addkey"))) {
        addKey();
      } else if (args[0].equals(Messages.getString("KeyczarTool.Pubkey"))) {
        publicKeys();
      } else if (args[0].equals(Messages.getString("KeyczarTool.Promote"))) {
        promote();
      } else if (args[0].equals(Messages.getString("KeyczarTool.Demote"))) {
        demote();
      } else if (args[0].equals(Messages.getString("KeyczarTool.Revoke"))) {
        revoke();
      } else if (args[0].equals(Messages.getString("KeyczarTool.Usekey"))
          && args.length > 2) {
        useKey(args[1]);
      } else { // unsupported command
        printUsage();
      }
    }
  }

  private static void useKey(String msg) throws KeyczarException {
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    if (destinationFlag == null) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MustDefinePublic"));
    }
    String answer = "";
    KeyczarReader reader = new KeyczarFileReader(locationFlag);
    if (crypterFlag != null) {
      Crypter keyCrypter = new Crypter(crypterFlag);
      reader = new KeyczarEncryptedReader(reader, keyCrypter);
    }
    
    switch (genericKeyczar.getMetadata().getPurpose()) {
      case DECRYPT_AND_ENCRYPT: 
        Crypter crypter = new Crypter(reader);
        answer = crypter.encrypt(msg);
        break;
      case SIGN_AND_VERIFY:
        Signer signer = new Signer(reader);
        answer = signer.sign(msg);
        break;
      default:
        throw new KeyczarException(
            Messages.getString("KeyczarTool.UnsupportedPurpose",
                genericKeyczar.getMetadata().getPurpose()));
    }
    genericKeyczar.writeFile(answer, destinationFlag);
  }

  /**
   * Adds key of given status to key set and pushes update to meta file. 
   * Requires location and status flags.
   * 
   * @throws KeyczarException if location flag is not set or
   * key type is unsupported
   */
  private static void addKey() throws KeyczarException {
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    if (sizeFlag == -1) { // use default size
      genericKeyczar.addVersion(statusFlag);
    } else { // use given size
      genericKeyczar.addVersion(statusFlag, sizeFlag);
    }
    if (crypterFlag != null) {
      Encrypter encrypter = new Encrypter(crypterFlag);
      updateGenericKeyczar(genericKeyczar, encrypter);
    } else {
      updateGenericKeyczar(genericKeyczar);
    }
  }
  
  /**
   * Creates a new KeyMetadata object, deciding its name, purpose and type
   * based on command line flags. Outputs its JSON representation in a file 
   * named meta in the directory given by the location flag.
   * 
   * @throws KeyczarException if location or purpose flags are not set
   */
  private static void create() throws KeyczarException {
    KeyMetadata kmd = null;
    if (purposeFlag == null) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MustDefinePurpose"));
    }
    switch (purposeFlag) {
      case TEST:
        kmd = new KeyMetadata(nameFlag, KeyPurpose.TEST, KeyType.TEST);
        break;
      case SIGN_AND_VERIFY:
        if (asymmetricFlag != null) {
          if (asymmetricFlag.equalsIgnoreCase("rsa")) {
            kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
                KeyType.RSA_PRIV);
          } else { // Default to DSA
            kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
                KeyType.DSA_PRIV);
          }
        } else { // HMAC-SHA1
          kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
              KeyType.HMAC_SHA1);
        }
        break;
      case DECRYPT_AND_ENCRYPT:
        if (asymmetricFlag != null) { // Default to RSA
          kmd = new KeyMetadata(nameFlag, KeyPurpose.DECRYPT_AND_ENCRYPT,
              KeyType.RSA_PRIV);
        } else { // AES
          kmd = new KeyMetadata(nameFlag, KeyPurpose.DECRYPT_AND_ENCRYPT,
              KeyType.AES);
        }
        break;
    }
    if (kmd == null) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.UnsupportedPurpose", purposeFlag));
    }
    if (mock == null) {
      if (locationFlag == null) {
        throw new KeyczarException(
            Messages.getString("KeyczarTool.MustDefineLocation"));
      }
      File file = new File(locationFlag + KeyczarFileReader.META_FILE);
      if (file.exists()) {
        throw new KeyczarException(
            Messages.getString("KeyczarTool.FileExists", file));
      }
      try {
        FileOutputStream metaOutput = new FileOutputStream(file);
        metaOutput.write(kmd.toString().getBytes());
        metaOutput.close();
      } catch (IOException e) {
        throw new KeyczarException(Messages.getString(
            "KeyczarTool.UnableToWrite", file.toString()), e);
      }
    } else { // for testing purposes, update mock kmd
      mock.setMetadata(kmd);
    }
  }

  /**
   * If the version flag is set, promotes the status of given key version.
   * Pushes update to meta file. Requires location and version flags.
   * 
   * @throws KeyczarException if location or version flag is not set
   * or promotion is illegal.
   */
  private static void promote() throws KeyczarException {
    if (versionFlag < 0) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MissingVersion"));
    }
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    genericKeyczar.promote(versionFlag);
    updateGenericKeyczar(genericKeyczar);
  }

  /**
   * If the version flag is set, demotes the status of given key version.
   * Pushes update to meta file. Requires location and version flags.
   * 
   * @throws KeyczarException if location or version flag is not set
   * or demotion is illegal.
   */
  private static void demote() throws KeyczarException {
    if (versionFlag < 0) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MissingVersion"));
    }
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    genericKeyczar.demote(versionFlag);
    updateGenericKeyczar(genericKeyczar);
  }
  
  /**
   * Creates and exports public key files to given destination based on 
   * private key set at given location.
   * 
   * @throws KeyczarException if location or destination flag is not set.
   */
  private static void publicKeys() throws KeyczarException {
    if (mock == null && destinationFlag == null) { // only if not testing
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MustDefineDestination"));
    }
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    genericKeyczar.publicKeyExport(destinationFlag);
  }

  /**
   * If the version flag is set, revokes the key of the given version.
   * Pushes update to meta file. Deletes old key file. Requires location
   * and version flags.
   * 
   * @throws KeyczarException if location or version flag is not set or if
   * unable to delete revoked key file.
   */
  private static void revoke() throws KeyczarException {
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    genericKeyczar.revoke(versionFlag);
    updateGenericKeyczar(genericKeyczar); // update meta files, key files
    if (mock == null) { // not necessary for testing
      File revokedVersion = new File(locationFlag + versionFlag);
      // TODO: Can we do anything to ensure that the file can't just be
      // undeleted? Maybe overwrite it with zeros first, although that might not
      // make a difference if the current version is cached. Probably better to
      // keep all key material encrypted on disk.
      if (!revokedVersion.delete()) { // delete old key file
        throw new KeyczarException("Unable to delete revoked key file."); //$NON-NLS-1$
      }
    } else {
      mock.removeKey(versionFlag);
    }
  }

  /**
   * Prints the usage instructions with list of commands and flags.
   */
  private static void printUsage() {
    // TODO: Move this to an external file
    String msg = "Usage:\t\"KeyczarTool command flags\"\n" + //$NON-NLS-1$
                 "Commands (optional paramters in [brackets]):\n" +  //$NON-NLS-1$
                 "create --location=location --purpose=purpose [--name=name]" + //$NON-NLS-1$
                     "[--asymmetric=rsa|dsa]\n" + //$NON-NLS-1$
                 "\tCreates a new key store.\n" +  //$NON-NLS-1$
                 "addkey --location=location [--status=status]" + //$NON-NLS-1$
                 " [--size=size] [--crypter=crypterLocation]\n" + //$NON-NLS-1$
                 "\tAdds new key with given status, size to given location." + //$NON-NLS-1$
                 "The default status is ACTIVE.\n" +  //$NON-NLS-1$
                 "pubkey --location=location --destination=destination\n" + //$NON-NLS-1$
                 "\tExport a key set at the given location as a set of " +  //$NON-NLS-1$
                     "public keys at a given destination.\n" +  //$NON-NLS-1$
                 "promote --location=location --version=versionNumber\n" + //$NON-NLS-1$
                 "\tPromote status of given key version at given location.\n" + //$NON-NLS-1$
                 "demote --location=location --version=versionNumber\n" + //$NON-NLS-1$
                 "\tDemote status of given key version at given location.\n" + //$NON-NLS-1$
                 "revoke --location=location --version=versionNumber\n" + //$NON-NLS-1$
                 "\tRevoke given key at given location if scheduled to be.\n" + //$NON-NLS-1$
                 "Flags:\n" +  //$NON-NLS-1$
                 "\t--name : Define the name of a keystore. Optional.\n" +  //$NON-NLS-1$
                 "\t--location : Define the file location of a keystore\n" +  //$NON-NLS-1$
                 "\t--destination : Define the destination location of " +  //$NON-NLS-1$
                     "a keystore.\n" +  //$NON-NLS-1$
                 "\t--purpose : Define the purpose of a keystore." +  //$NON-NLS-1$
                     " Must be sign, crypt, or test.\n" +  //$NON-NLS-1$
                 "\t--status : Define the status of a new key. Must be " + //$NON-NLS-1$
                     "primary, active, or scheduled_for_revocation. Optional." + //$NON-NLS-1$
                     " Defaults to active.\n" + //$NON-NLS-1$
                     "\t--crypter : The location of a crypter to be used for" + //$NON-NLS-1$
                     " encrypting new keys \n" +  //$NON-NLS-1$
                 "\t--version : The version number of key to update.\n" + //$NON-NLS-1$
                 "\t--size : Key size in bits. Overrides default. Optional.\n" + //$NON-NLS-1$
                 "\t--asymmetric : Dictate use of asymmetric algorithm. " + //$NON-NLS-1$
                 "Must be rsa or blank. Optional.\n\t\t\t" + //$NON-NLS-1$
                 "For sign, defaults to DSA unless rsa indicated. " + //$NON-NLS-1$
                 "For crypt, uses RSA.\n" + //$NON-NLS-1$
                 "\t--crypter : The location of a crypter that will " + //$NON-NLS-1$
                 "encrypt a keyset on disk\n" + //$NON-NLS-1$
                 "Key Sizes: (default first)\n" + //$NON-NLS-1$
                 "AES : 128\n" + //$NON-NLS-1$
                 "HMAC-SHA1 : 256\n" + //$NON-NLS-1$
                 "DSA : 1024\n" + //$NON-NLS-1$
                 "RSA : 2048, 1024, 768, 512\n"; //$NON-NLS-1$
    System.out.println(msg);
  }
  
  /**
   * Parses command line arguments and sets appropriate flags.
   * 
   * @param args from the command line
   */
  private static void setFlags(String[] args) {
    HashMap<String, String> params = new HashMap<String, String>();
    
    for (String arg : args) {
      if (arg.startsWith("--")) {
        arg = arg.substring(2); // Trim off the leading dashes
        String[] nameValuePair = arg.split("=");
        if (nameValuePair.length == 2) {
          params.put(nameValuePair[0], nameValuePair[1]);
        } else if (nameValuePair.length == 1) {
          params.put(nameValuePair[0], "true");
        }
      }
    }
    
    locationFlag = params.get("location");
    if (locationFlag != null && !locationFlag.endsWith(File.separator)) {
      locationFlag += File.separator;
    }

    destinationFlag = params.get("destination");
    if (destinationFlag != null && !destinationFlag.endsWith(File.separator)) {
      destinationFlag += File.separator;
    }

    nameFlag = params.get("name");
    purposeFlag = KeyPurpose.getPurpose(params.get("purpose"));
    statusFlag = KeyStatus.getStatus(params.get("status")); // default ACTIVE
    asymmetricFlag = params.get("asymmetric");
    crypterFlag = params.get("crypter");
    
    try {
      versionFlag = Integer.parseInt(params.get("version"));
    } catch (NumberFormatException e) {
      versionFlag = -1; // mark flag as unset, handle above
    }
    try {
      sizeFlag = Integer.parseInt(params.get("size")); //$NON-NLS-1$
    } catch (NumberFormatException e) {
      sizeFlag = -1; // mark flag as unset, handle above
    }
  }
  
  /**
   * Creates a GenericKeyczar object based on locationFlag if it is set.
   * Alternatively, it can use the mock KeyczarReader if it is set.
   * 
   * @return GenericKeyczar if locationFlag set
   * @throws KeyczarException if locationFlag not set
   */
  private static GenericKeyczar createGenericKeyczar() throws KeyczarException {
    if (mock != null) {
      return new GenericKeyczar(mock);
    }
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the " //$NON-NLS-1$
          + "--location flag"); //$NON-NLS-1$
    }
    KeyczarReader reader = new KeyczarFileReader(locationFlag);
    if (crypterFlag != null) {
      Crypter keyDecrypter = new Crypter(crypterFlag);
      reader = new KeyczarEncryptedReader(reader, keyDecrypter);
    }
    return new GenericKeyczar(reader);
  }
  
  private static void updateGenericKeyczar(GenericKeyczar genericKeyczar) 
      throws KeyczarException {
    updateGenericKeyczar(genericKeyczar, null);
  }
  
  private static void updateGenericKeyczar(GenericKeyczar genericKeyczar, 
      Encrypter encrypter) throws KeyczarException {
    if (mock != null) {
      mock.setMetadata(genericKeyczar.getMetadata()); // update metadata
      for (KeyVersion version : genericKeyczar.getVersions()) {
        mock.setKey(version.getVersionNumber(), genericKeyczar.getKey(version));
      } // update key data
    } else if (encrypter != null) {
      genericKeyczar.writeEncrypted(locationFlag, encrypter);
    } else {
      genericKeyczar.write(locationFlag);
    }
  }

  /**
   * Wrapper class to access Keyczar utility methods of reading and manipulating
   * key metadata files. Also contains additional utility methods for pushing
   * updates to meta files on disk and exporting public key sets.
   *
   * @author steveweis@gmail.com (Steve Weis)
   * @author arkajit.dey@gmail.com (Arkajit Dey)
   */
  private static class GenericKeyczar extends Keyczar {
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
        throw new KeyczarException("Cannot export public keys for key type: " //$NON-NLS-1$
            + kmd.getType() + " and purpose " + kmd.getPurpose()); //$NON-NLS-1$
      }
      
      for (KeyVersion version : getVersions()) {
        KeyczarKey publicKey =
          ((KeyczarPrivateKey) getKey(version)).getPublic();
        if (mock == null) {
          writeFile(publicKey.toString(), destination
              + version.getVersionNumber());
        } else { // for testing, update mock object
          mock.setPublicKey(version.getVersionNumber(), publicKey);
        }
        publicKmd.addVersion(version);
      }
      if (mock == null) {
        writeFile(publicKmd.toString(), destination
            + KeyczarFileReader.META_FILE);
      } else { // for testing, update mock public kmd
        mock.setPublicKeyMetadata(publicKmd);
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
      writeFile(getMetadata().toString(), location
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
    private void writeFile(String data, String location)
        throws KeyczarException {
      File outputFile = new File(location);
      try {
        FileWriter writer = new FileWriter(outputFile);
        writer.write(data);
        writer.close();
      } catch (IOException e) {
        throw new KeyczarException("Unable to write to : " //$NON-NLS-1$
            + outputFile.toString(), e);
      }
    }
  }
}
