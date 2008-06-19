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

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;


/**
 * Command line tool for generating Keyczar key files.
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
  static KeyPurpose purposeFlag;
  static KeyStatus statusFlag = KeyStatus.ACTIVE;

  public static void main(String[] args) throws Exception {
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
      } else if (args[0].equals("setstatus")) {
        setStatus();
      } else { // unsupported command
        printUsage();
      }
    }
  }

  private static void addKey() throws KeyczarException {
    // Read existing metadata
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the "
          + "--location flag");
    }
    GenericKeyczar genericKeyczar = new GenericKeyczar(locationFlag);
    genericKeyczar.addVersion(statusFlag);
    genericKeyczar.write(locationFlag);
  }
  
  /**
   * Creates a new KeyMetadata object, deciding its name, purpose and type
   * based on command line flags. Outputs its JSON representation in a file 
   * named meta in the directory given by the --location flag.
   * 
   * @throws KeyczarException
   */
  private static void create() throws KeyczarException {
    KeyMetadata kmd = null;
    if (purposeFlag == null) {
      throw new KeyczarException("Must define a key set purpose with the "
          + "--purpose flag. Valid purposes are sign, crypt, and test.");
    }
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the "
          + "--location flag.");
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
    File file = new File(locationFlag + KeyczarFileReader.META_FILE);
    if (file.exists()) {
      throw new KeyczarException("File already exists: " + file);
    }

    try {
      FileOutputStream metaOutput = new FileOutputStream(file);
      metaOutput.write(kmd.toString().getBytes());
      metaOutput.close();
    } catch (IOException e) {
      throw new KeyczarException("Unable to write to : " + file.toString(), e);
    }
  }

  private static void printUsage() {
    // TODO: document --asymmetric flag, setstatus command
    String msg = "Usage:\t\"KeyczarTool command flags\"\n" +
                 "Commands:\n" + 
                 "create --name=name --location=location --purpose=purpose\n" +
                 "\tCreates a new key store\n" + 
                 "addkey --location=location --status=status\n" + 
                 "pubkey --location=location --destination=destination\n" +
                 "\tExport a key set at the given location as a set of " + 
                   "public keys at a given destination.\n" + 
                 "Flags:\n" + 
                 "\t--name : Define the name of a keystore. Optional.\n" + 
                 "\t--location : Define the file location of a keystore\n" + 
                 "\t--destination : Define the destination location of " + 
                   "a keystore.\n" + 
                 "\t--purpose : Define the purpose of a keystore." + 
                   " Must be sign, crypt, or test.\n" + 
                 "\t--status : Define the status of a new key. Must be " +
                   "primary, active, or scheduled_for_revocation. Optional.";
    System.out.println(msg);
  }

  private static void publicKeys() throws KeyczarException {
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the "
          + "--location flag");
    }
    if (destinationFlag == null) {
      throw new KeyczarException("Must define a public key set location with"
          + " the --destination flag");
    }
    GenericKeyczar genericKeyczar = new GenericKeyczar(locationFlag);
    genericKeyczar.publicKeyExport(destinationFlag);
  }

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
    nameFlag = params.get("name");
    locationFlag = params.get("location");
    if (locationFlag != null && !locationFlag.endsWith(File.separator)) {
      locationFlag += File.separator;
    }

    destinationFlag = params.get("destination");
    if (destinationFlag != null && !destinationFlag.endsWith(File.separator)) {
      destinationFlag += File.separator;
    }

    purposeFlag = KeyPurpose.getPurpose(params.get("purpose"));
    //TODO: What about other purposes? ENCRYPT, VERIFY not included originally
    // also invalid purpose makes flag null, OK?
    statusFlag = KeyStatus.getStatus(params.get("status")); // default ACTIVE
    asymmetricFlag = params.get("asymmetric");
  }
  
  private static void setStatus() throws KeyczarException {
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the "
          + "--location flag");
    }
    
    //TODO(arkajit.dey): finish implementing setStatus() method
  }

  private static class GenericKeyczar extends Keyczar {
    GenericKeyczar(String location) throws KeyczarException {
      super(location);
    }

    @Override
    boolean isAcceptablePurpose(KeyPurpose purpose) {
      return true;
    }

    void publicKeyExport(String destination) throws KeyczarException {
      KeyMetadata kmd = getMetadata();
      // Can only export if type is DSA_PRIV and purpose is SIGN_AND_VERIFY
      KeyMetadata publicKmd = null;
      if (kmd.getType() == KeyType.DSA_PRIV
          && kmd.getPurpose() == KeyPurpose.SIGN_AND_VERIFY) {
        publicKmd = new KeyMetadata(kmd.getName(), KeyPurpose.VERIFY,
            KeyType.DSA_PUB);
      } else if (kmd.getType() == KeyType.RSA_PRIV) {
        if (kmd.getPurpose() == KeyPurpose.DECRYPT_AND_ENCRYPT) {
          publicKmd = new KeyMetadata(kmd.getName(), KeyPurpose.ENCRYPT,
              KeyType.RSA_PUB);
        } else if (kmd.getPurpose() == KeyPurpose.SIGN_AND_VERIFY) {
          publicKmd = new KeyMetadata(kmd.getName(), KeyPurpose.VERIFY,
              KeyType.RSA_PUB);
        }
      }
      if (publicKmd == null) {
        throw new KeyczarException("Cannot export public keys for key type: "
            + kmd.getType() + " and purpose " + kmd.getPurpose());
      }
      Iterator<KeyVersion> versions = getVersions();
      while (versions.hasNext()) {
        KeyVersion version = versions.next();
        KeyczarKey publicKey = ((KeyczarPrivateKey) getKey(version))
            .getPublic();
        writeFile(publicKey.toString(), destination
            + version.getVersionNumber());
        publicKmd.addVersion(version);
      }
      writeFile(publicKmd.toString(), destination + KeyczarFileReader.META_FILE);
    }

    void write(String location) throws KeyczarException {
      writeFile(getMetadata().toString(), location
          + KeyczarFileReader.META_FILE);
      Iterator<KeyVersion> versions = getVersions();
      while (versions.hasNext()) {
        KeyVersion version = versions.next();
        writeFile(getKey(version).toString(), location
            + version.getVersionNumber());
      }
    }

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