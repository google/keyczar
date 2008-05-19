// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import keyczar.interfaces.PublicKeyExportable;

/**
 * Command line tool for generating Keyczar key files
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class KeyczarTool {
  static String nameFlag;
  static String locationFlag;
  static String destinationFlag;
  static KeyPurpose purposeFlag;
  static KeyStatus statusFlag = KeyStatus.ACTIVE;
  static boolean asymmetricFlag;
  
  private static class GenericKeyczar extends Keyczar {
    public GenericKeyczar(String location) throws KeyczarException {
      super(location);
    }

    @Override
    protected boolean isAcceptablePurpose(KeyPurpose purpose) {
      return true;
    }

    private void writeFile(String data, String location)
        throws KeyczarException {
      File outputFile = new File(location);
      try {
        FileWriter writer = new FileWriter(outputFile);
        writer.write(data);
        writer.close();
      } catch (IOException e) {
        throw new KeyczarException("Unable to write to : " +
            outputFile.toString(), e);
      }
    }
    
    void write(String location) throws KeyczarException {
      writeFile(this.getMetadata().toString(),
          location + KeyczarFileReader.META_FILE);
      Iterator<KeyVersion> versions = getVersions();
      while (versions.hasNext()) {
        KeyVersion version = versions.next();
        writeFile(getKey(version).toString(),
            location + version.getVersionNumber());
      }
    }
    
    void publicKeyExport(String destination) throws KeyczarException {
      KeyMetadata kmd = getMetadata();
      // Can only export if type is DSA_PRIV and purpose is SIGN_AND_VERIFY
      if (kmd.getType() == KeyType.DSA_PRIV &&
          kmd.getPurpose() == KeyPurpose.SIGN_AND_VERIFY) {
        KeyMetadata publicKmd =
          new KeyMetadata(kmd.getName(), KeyPurpose.VERIFY, KeyType.DSA_PUB);
        Iterator<KeyVersion> versions = getVersions();
        while (versions.hasNext()) {
          KeyVersion version = versions.next();
          KeyczarKey publicKey =
            ((PublicKeyExportable) getKey(version)).getPublic();
          writeFile(publicKey.toString(),
              destination + version.getVersionNumber());
          publicKmd.addVersion(version);
        } 
        writeFile(publicKmd.toString(),
            destination + KeyczarFileReader.META_FILE);
      } else {
        throw new KeyczarException("Cannot export public keys for key type: " +
            kmd.getType() + " and purpose " + kmd.getPurpose());
      }
    }
  }
    
  private static void addKey() throws KeyczarException {
    // Read existing metadata
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the " +
          "--location flag");
    }
    GenericKeyczar genericKeyczar = new GenericKeyczar(locationFlag);
    genericKeyczar.addVersion(statusFlag);
    genericKeyczar.write(locationFlag);
  }
  
  private static void create() throws KeyczarException {
    KeyMetadata kmd = null;
    if (purposeFlag == null) {
      throw new KeyczarException("Must define a key set purpose with the " +
          "--purpose flag. Valid purposes are sign, crypt, and test.");
    }
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the " +
          "--location flag");
    }
    switch (purposeFlag) {
      case TEST:
        kmd = new KeyMetadata(nameFlag, KeyPurpose.TEST, KeyType.TEST);
        break;
      case SIGN_AND_VERIFY:
        kmd = new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY,
            (asymmetricFlag ? KeyType.DSA_PRIV : KeyType.HMAC_SHA1));
        break;
      case DECRYPT_AND_ENCRYPT:
        kmd =
          new KeyMetadata(nameFlag, KeyPurpose.DECRYPT_AND_ENCRYPT, KeyType.AES);
        break;
      case VERIFY:
        // For sets of public signing keys only
      case ENCRYPT:
        // For sets of public crypting keys only
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
  
  private static void publicKeys() throws KeyczarException {
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the " +
          "--location flag");
    }
    if (destinationFlag == null) {
      throw new KeyczarException("Must define a public key set location with" +
          " the --destination flag");
    }
    GenericKeyczar genericKeyczar = new GenericKeyczar(locationFlag);
    genericKeyczar.publicKeyExport(destinationFlag);
  }

  
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
    asymmetricFlag = (params.get("asymmetric") != null);
  } 
  
  private static void printUsage() {
    System.out.print("Usage:");
    System.out.println("\t\"KeyczarTool command flags\"");
    System.out.println("Commands:");
    System.out.println("\tcreate --name=name --location=location " + 
        "--purpose=purpose: Creates a new key store");
    System.out.println("\taddkey --location=location --status=status " + 
    ": Adds a new key to a store in the existing location.");
    System.out.println("\tpubkey --location=location --destination=destination" +
        " : Export a key set at the given location as a set of public keys at" +
        " a given destination.");
    System.out.println("Flags:");
    System.out.println("\t--name : Define the name of a keystore. Optional.");
    System.out.println("\t--location : Define the file location of a keystore");
    System.out.println("\t--destination : Define the destination location of a keystore");
    System.out.println("\t--purpose : Define the purpose of a keystore. " + 
        "Must be sign, crypt, or test.");
    System.out.println("\t--status : Define the status of a new key. " + 
        "Must be primary, active, or scheduled_for_revocation. Optional.");
    
  }
}
