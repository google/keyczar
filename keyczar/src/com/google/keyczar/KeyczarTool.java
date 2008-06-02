// Keyczar (http://code.google.com/p/keyczar/) 2008

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
 * Command line tool for generating Keyczar key files
 * 
 * @author steveweis@gmail.com (Steve Weis)
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

  private static void create() throws KeyczarException {
    KeyMetadata kmd = null;
    if (purposeFlag == null) {
      throw new KeyczarException("Must define a key set purpose with the "
          + "--purpose flag. Valid purposes are sign, crypt, and test.");
    }
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the "
          + "--location flag");
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
        } else {
          // Default to DSA
          kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
              KeyType.DSA_PRIV);
        }
      } else {
        kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
            KeyType.HMAC_SHA1);
      }
      break;
    case DECRYPT_AND_ENCRYPT:
      if (asymmetricFlag != null) {
        kmd = new KeyMetadata(nameFlag, KeyPurpose.DECRYPT_AND_ENCRYPT,
            KeyType.RSA_PRIV);
      } else {
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
    // TODO: Clean this up
    System.out.print("Usage:");
    System.out.println("\t\"KeyczarTool command flags\"");
    System.out.println("Commands:");
    System.out
        .println("create --name=name --location=location --purpose=purpose");
    System.out.println("\tCreates a new key store");
    System.out.println("addkey --location=location --status=status ");
    System.out
        .println("\tpubkey --location=location --destination=destination");
    System.out
        .println("\tExport a key set at the given location as a set of public keys at a given destination.");
    System.out.println("Flags:");
    System.out.println("\t--name : Define the name of a keystore. Optional.");
    System.out.println("\t--location : Define the file location of a keystore");
    System.out
        .println("\t--destination : Define the destination location of a keystore");
    System.out.println("\t--purpose : Define the purpose of a keystore. "
        + "Must be sign, crypt, or test.");
    System.out.println("\t--status : Define the status of a new key. "
        + "Must be primary, active, or scheduled_for_revocation. Optional.");

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
        // Trim off the leading dashes
        arg = arg.substring(2);
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

    if (params.get("purpose") != null) {
      if (params.get("purpose").equals("sign")) {
        purposeFlag = KeyPurpose.SIGN_AND_VERIFY;
      } else if (params.get("purpose").equals("crypt")) {
        purposeFlag = KeyPurpose.DECRYPT_AND_ENCRYPT;
      } else if (params.get("purpose").equals("test")) {
        purposeFlag = KeyPurpose.TEST;
      }
    }

    if (params.get("status") != null) {
      if (params.get("status").equals("primary")) {
        statusFlag = KeyStatus.PRIMARY;
      } else if (params.get("status").equals("active")) {
        statusFlag = KeyStatus.ACTIVE;
      } else if (params.get("status").equals("scheduled_for_revocation")) {
        statusFlag = KeyStatus.SCHEDULED_FOR_REVOCATION;
      }
    }
    asymmetricFlag = params.get("asymmetric");
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
