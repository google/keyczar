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

package com.google.keyczar;

import com.google.keyczar.enums.KeyPurpose;
import com.google.keyczar.enums.KeyStatus;
import com.google.keyczar.enums.KeyType;
import com.google.keyczar.exceptions.KeyczarException;
import com.google.keyczar.interfaces.KeyczarReader;

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
      if (args[0].equals("create")) {
        create();
      } else if (args[0].equals("addkey")) {
        addKey();
      } else if (args[0].equals("pubkey")) {
        publicKeys();
      } else if (args[0].equals("promote")) {
        promote();
      } else if (args[0].equals("demote")) {
        demote();
      } else if (args[0].equals("revoke")) {
        revoke();
      } else if (args[0].equals("usekey") && args.length > 2) {
        useKey(args[1]);
      } else { // unsupported command
        printUsage();
      }
    }
  }

  private static void useKey(String msg) throws KeyczarException {
    GenericKeyczar genericKeyczar = createGenericKeyczar();
    if (destinationFlag == null) {
      throw new KeyczarException("Must define a public key set location with"
          + " the --destination flag");
    }
    String answer = "";
    switch (genericKeyczar.getMetadata().getPurpose()) {
      case DECRYPT_AND_ENCRYPT: 
        Crypter crypter = new Crypter(locationFlag);
        answer = crypter.encrypt(msg);
        break;
      case SIGN_AND_VERIFY:
        Signer signer = new Signer(locationFlag);
        answer = signer.sign(msg);
        break;
      default:
        throw new KeyczarException("Unsupported purpose!");
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
    updateGenericKeyczar(genericKeyczar);
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
      throw new KeyczarException("Must define a key set purpose with the "
          + "--purpose flag. Valid purposes are sign, crypt, and test.");
    }
    switch (purposeFlag) {
      case TEST:
        kmd = new KeyMetadata(nameFlag, KeyPurpose.TEST, KeyType.TEST);
        break;
      case SIGN_AND_VERIFY:
        if (asymmetricFlag != null) {
          if (asymmetricFlag.equalsIgnoreCase("rsa")) { // RSA
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
      throw new KeyczarException("Unsupported purpose: " + purposeFlag);
    }
    if (mock == null) {
      if (locationFlag == null) {
        throw new KeyczarException("Must define a key set location with the "
            + "--location flag.");
      }
      File file = new File(locationFlag + KeyczarFileReader.META_FILE);
      if (file.exists()) {
        throw new KeyczarException("File already exists: " + file);
      }
      try {
        FileOutputStream metaOutput = new FileOutputStream(file);
        metaOutput.write(kmd.toString().getBytes());
        metaOutput.close();
      } catch (IOException e) {
        throw new KeyczarException("Unable to write to : " + 
            file.toString(), e);
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
      throw new KeyczarException("Illegal or missing version number.");
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
      throw new KeyczarException("Illegal or missing version number.");
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
      throw new KeyczarException("Must define a public key set location with"
          + " the --destination flag");
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
      if (!revokedVersion.delete()) { // delete old key file
        throw new KeyczarException("Unable to delete revoked key file.");
      }
    } else {
      mock.removeKey(versionFlag);
    }
  }

  /**
   * Prints the usage instructions with list of commands and flags.
   */
  private static void printUsage() {
    String msg = "Usage:\t\"KeyczarTool command flags\"\n" +
                 "Commands:\n" + 
                 "create --name=name --location=location --purpose=purpose " +
                     "--asymmetric=rsa|dsa\n" +
                 "\tCreates a new key store.\n" + 
                 "addkey --location=location --status=status --size=size\n" +
                 "\tAdds new key with given status, size to given location.\n" + 
                 "pubkey --location=location --destination=destination\n" +
                 "\tExport a key set at the given location as a set of " + 
                     "public keys at a given destination.\n" + 
                 "promote --location=location --version=versionNumber\n" +
                 "\tPromote status of given key version at given location.\n" +
                 "demote --location=location --version=versionNumber\n" +
                 "\tDemote status of given key version at given location.\n" +
                 "revoke --location=location --version=versionNumber\n" +
                 "\tRevoke given key at given location if scheduled to be.\n" +
                 "Flags:\n" + 
                 "\t--name : Define the name of a keystore. Optional.\n" + 
                 "\t--location : Define the file location of a keystore\n" + 
                 "\t--destination : Define the destination location of " + 
                     "a keystore.\n" + 
                 "\t--purpose : Define the purpose of a keystore." + 
                     " Must be sign, crypt, or test.\n" + 
                 "\t--status : Define the status of a new key. Must be " +
                     "primary, active, or scheduled_for_revocation. Optional." +
                     " Defaults to active.\n" +
                 "\t--version : The version number of key to update.\n" +
                 "\t--size : Key size in bits. Overrides default. Optional.\n" +
                 "\t--asymmetric : Dictate use of asymmetric algorithm. " +
                     "Must be rsa or blank. Optional.\n\t\t\t" +
                     "For sign, defaults to DSA unless rsa indicated. " +
                     "For crypt, uses RSA.\n" +
                 "Key Sizes: (default first)\n" +
                 "AES : 128\n" +
                 "HMAC-SHA1 : 256\n" +
                 "DSA : 1024\n" +
                 "RSA : 2048, 1024, 768, 512\n";
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
    try {
      versionFlag = Integer.parseInt(params.get("version"));
    } catch (NumberFormatException e) {
      versionFlag = -1; // mark flag as unset, handle above
    }
    try {
      sizeFlag = Integer.parseInt(params.get("size"));
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
      throw new KeyczarException("Must define a key set location with the "
          + "--location flag");
    }
    return new GenericKeyczar(locationFlag);
  }
  
  private static void updateGenericKeyczar(GenericKeyczar genericKeyczar) 
      throws KeyczarException {
    if (mock != null) {
      mock.setMetadata(genericKeyczar.getMetadata()); // update metadata
      for (KeyVersion version : genericKeyczar.getVersions()) {
        mock.setKey(version.getVersionNumber(), genericKeyczar.getKey(version));
      } // update key data
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
        throw new KeyczarException("Cannot export public keys for key type: "
            + kmd.getType() + " and purpose " + kmd.getPurpose());
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
        throw new KeyczarException("Unable to write to : "
            + outputFile.toString(), e);
      }
    }
  }
}