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

import org.keyczar.enums.Command;
import org.keyczar.enums.Flag;
import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

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
   * Returns a mock for testing purposes
   *
   * @return A mock KeyCzar reader
   */
  public static MockKeyczarReader getMock() {
    return mock;
  }

  /**
   * Uses setFlags() to parse command line arguments and delegates to the
   * appropriate command function or prints the usage instructions if command
   * syntax is invalid.
   *
   * @param args from the command line
   */
  public static void main(String[] args){
    if (args.length == 0) {
      printUsage();
    } else {
      try {
        Command c = Command.getCommand(args[0]);
        HashMap<Flag, String> flagMap = new HashMap<Flag, String>();
        for (String arg : args) {
          if (arg.startsWith("--")) {
            arg = arg.substring(2); // Trim off the leading dashes
            String[] nameValuePair = arg.split("=");
            if (nameValuePair.length > 1) {
              Flag f = Flag.getFlag(nameValuePair[0]);
              flagMap.put(f, nameValuePair[1]);
            }
          }
        }

        // All commands need a location.
        String locationFlag = flagMap.get(Flag.LOCATION);
        if (locationFlag != null && !locationFlag.endsWith(File.separator)) {
          locationFlag += File.separator;
        }

        switch (c) {
          case CREATE:
            String nameFlag = flagMap.get(Flag.NAME);
            KeyPurpose purposeFlag =
              KeyPurpose.getPurpose(flagMap.get(Flag.PURPOSE));
            String asymmetricFlag = flagMap.get(Flag.ASYMMETRIC);
            create(locationFlag, nameFlag, purposeFlag, asymmetricFlag); break;
          case ADDKEY:
            KeyStatus statusFlag = KeyStatus.getStatus(
                                                      flagMap.get(Flag.STATUS));
            String crypterFlag = flagMap.get(Flag.CRYPTER);
            int sizeFlag = -1;
            if (flagMap.containsKey(Flag.SIZE)) {
              sizeFlag = Integer.parseInt(flagMap.get(Flag.SIZE));
            }
            addKey(locationFlag, statusFlag, crypterFlag, sizeFlag);
            break;
          case PUBKEY:
            publicKeys(locationFlag, flagMap.get(Flag.DESTINATION));
            break;
          case PROMOTE:
            promote(locationFlag, Integer.parseInt(flagMap.get(Flag.VERSION)));
            break;
          case DEMOTE:
            demote(locationFlag, Integer.parseInt(flagMap.get(Flag.VERSION)));
            break;
          case REVOKE:
            revoke(locationFlag, Integer.parseInt(flagMap.get(Flag.VERSION)));
            break;
          case USEKEY:
            if (args.length > 2) {
              useKey(args[1], locationFlag, flagMap.get(Flag.DESTINATION),
                    flagMap.get(Flag.CRYPTER));
            } else {
              printUsage();
            }
            break;
        }
      } catch (NumberFormatException e) {
        e.printStackTrace();
        printUsage();
      } catch (IllegalArgumentException e) {
        e.printStackTrace();
        printUsage();
      } catch (NullPointerException e) {
        e.printStackTrace();
        printUsage();
      } catch (KeyczarException e) {
        e.printStackTrace();
        printUsage();
      }
    }
  }

  private static void useKey(String msg, String locationFlag,
      String destinationFlag, String crypterFlag) throws KeyczarException {
    GenericKeyczar genericKeyczar =
      createGenericKeyczar(locationFlag, crypterFlag);
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
   * @param sizeFlag
   * @param crypterFlag
   * @param statusFlag
   * @param locationFlag
   *
   * @throws KeyczarException if location flag is not set or
   * key type is unsupported
   */
  private static void addKey(String locationFlag, KeyStatus statusFlag,
      String crypterFlag, int sizeFlag) throws KeyczarException {
    GenericKeyczar genericKeyczar =
      createGenericKeyczar(locationFlag, crypterFlag);
    if (sizeFlag == -1) { // use default size
      genericKeyczar.addVersion(statusFlag);
    } else { // use given size
      genericKeyczar.addVersion(statusFlag, sizeFlag);
    }
    if (crypterFlag != null) {
      Encrypter encrypter = new Encrypter(crypterFlag);
      updateGenericKeyczar(genericKeyczar, encrypter, locationFlag);
    } else {
      updateGenericKeyczar(genericKeyczar, locationFlag);
    }
  }

  /**
   * Creates a new KeyMetadata object, deciding its name, purpose and type
   * based on command line flags. Outputs its JSON representation in a file
   * named meta in the directory given by the location flag.
   * @param asymmetricFlag
   * @param purposeFlag
   * @param nameFlag
   * @param locationFlag
   *
   * @throws KeyczarException if location or purpose flags are not set
   */
  private static void create(String locationFlag, String nameFlag,
      KeyPurpose purposeFlag, String asymmetricFlag) throws KeyczarException {
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
          } else if (asymmetricFlag.equalsIgnoreCase("ec")) {
                kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
                    KeyType.EC_PRIV);
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
   * @param versionFlag The version to promote
   * @param locationFlag The location of the key set
   *
   * @throws KeyczarException if location or version flag is not set
   * or promotion is illegal.
   */
  private static void promote(String locationFlag, int versionFlag)
      throws KeyczarException {
    if (versionFlag < 0) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MissingVersion"));
    }
    GenericKeyczar genericKeyczar = createGenericKeyczar(locationFlag);
    genericKeyczar.promote(versionFlag);
    updateGenericKeyczar(genericKeyczar, locationFlag);
  }

  /**
   * If the version flag is set, demotes the status of given key version.
   * Pushes update to meta file. Requires location and version flags.
   * @param versionFlag The verion to demote
   * @param locationFlag The location of the key set
   *
   * @throws KeyczarException if location or version flag is not set
   * or demotion is illegal.
   */
  private static void demote(String locationFlag, int versionFlag)
      throws KeyczarException {
    if (versionFlag < 0) {
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MissingVersion"));
    }
    GenericKeyczar genericKeyczar = createGenericKeyczar(locationFlag);
    genericKeyczar.demote(versionFlag);
    updateGenericKeyczar(genericKeyczar, locationFlag);
  }

  /**
   * Creates and exports public key files to given destination based on
   * private key set at given location.
   * @param destinationFlag Destionation of public keys
   * @param locationFlag Location of private key set
   *
   * @throws KeyczarException if location or destination flag is not set.
   */
  private static void publicKeys(String locationFlag, String destinationFlag)
      throws KeyczarException {
    if (mock == null && destinationFlag == null) { // only if not testing
      throw new KeyczarException(
          Messages.getString("KeyczarTool.MustDefineDestination"));
    }
    GenericKeyczar genericKeyczar = createGenericKeyczar(locationFlag);
    genericKeyczar.publicKeyExport(destinationFlag);
  }

  /**
   * If the version flag is set, revokes the key of the given version.
   * Pushes update to meta file. Deletes old key file. Requires location
   * and version flags.
   * @param versionFlag The version to revoke
   * @param locationFlag The location of the key set
   *
   * @throws KeyczarException if location or version flag is not set or if
   * unable to delete revoked key file.
   */
  private static void revoke(String locationFlag, int versionFlag)
      throws KeyczarException {
    GenericKeyczar genericKeyczar = createGenericKeyczar(locationFlag);
    genericKeyczar.revoke(versionFlag);
    // update meta files, key files
    updateGenericKeyczar(genericKeyczar, locationFlag);
    if (mock == null) { // not necessary for testing
      File revokedVersion = new File(locationFlag + versionFlag);
      if (!revokedVersion.delete()) { // delete old key file
        throw new KeyczarException(
            Messages.getString("KeyczarTool.UnableToDelete"));
      }
    } else {
      mock.removeKey(versionFlag);
    }
  }

  /**
   * Prints the usage instructions with list of commands and flags.
   */
  private static void printUsage() {
    ArrayList<String> usageParams = new ArrayList<String>();
    for (Command c : Command.values()) {
      usageParams.add(c.toString());
    }

    for (Flag f : Flag.values()) {
      usageParams.add(f.toString());
    }

    System.out.println(
        Messages.getString("KeyczarTool.Usage", usageParams.toArray()));
  }

  private static GenericKeyczar createGenericKeyczar(String locationFlag)
      throws KeyczarException {
    return createGenericKeyczar(locationFlag, null);
  }

  /**
   * Creates a GenericKeyczar object based on locationFlag if it is set.
   * Alternatively, it can use the mock KeyczarReader if it is set.
   * @param locationFlag The location of the key set
   * @param crypterFlag The location of a crypter to decrypt the key set
   * @return GenericKeyczar if locationFlag set
   * @throws KeyczarException if locationFlag not set
   */
  private static GenericKeyczar createGenericKeyczar(String locationFlag,
      String crypterFlag) throws KeyczarException {
    if (mock != null) {
      return new GenericKeyczar(mock);
    }
    if (locationFlag == null) {
      throw new KeyczarException(Messages.getString("KeyczarTool.NeedLocation",
          Messages.getString("KeyczarTool.Location")));
    }
    KeyczarReader reader = new KeyczarFileReader(locationFlag);
    if (crypterFlag != null) {
      Crypter keyDecrypter = new Crypter(crypterFlag);
      reader = new KeyczarEncryptedReader(reader, keyDecrypter);
    }
    return new GenericKeyczar(reader);
  }

  private static void updateGenericKeyczar(GenericKeyczar genericKeyczar,
      String locationFlag) throws KeyczarException {
    updateGenericKeyczar(genericKeyczar, null, locationFlag);
  }

  private static void updateGenericKeyczar(GenericKeyczar genericKeyczar,
      Encrypter encrypter, String locationFlag) throws KeyczarException {
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
}