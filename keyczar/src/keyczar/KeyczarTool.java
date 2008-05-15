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

/**
 * Command line tool for generating Keyczar key files
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class KeyczarTool {
  static String nameFlag;
  static String locationFlag;
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

    void write(String location) throws KeyczarException {
      File metaFile = new File(locationFlag + KeyczarFileReader.META_FILE);
      try {
        FileWriter metadataWriter = new FileWriter(metaFile);
        metadataWriter.write(this.toString());
        metadataWriter.close();
      } catch (IOException e) {
        throw new KeyczarException("Unable to write to : " +
            metaFile.toString(), e);
      }
      
      Iterator<KeyVersion> versions = getVersions();
      while (versions.hasNext()) {
        KeyVersion version = versions.next();
        File versionFile = new File(locationFlag + version.getVersionNumber());
        try {
          FileWriter versionWriter = new FileWriter(versionFile);
          versionWriter.write(getKey(version).toString());
          versionWriter.close();
          //FileOutputStream versionOutput = new FileOutputStream(versionFile);
          //DataPacker packer = new DataPacker(versionOutput);
          //writeVersion(version, packer);
        } catch (IOException e) {
          throw new KeyczarException("Unable to write to : " +
              versionFile.toString(), e);
        }
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
        kmd =
          new KeyMetadata(nameFlag, KeyPurpose.SIGN_AND_VERIFY, KeyType.HMAC_SHA1);
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
  
  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      printUsage();
    } else {
      setFlags(args);
      if (args[0].equals("create")) {
        create();
      } else if (args[0].equals("addkey")) {
        addKey();
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
    asymmetricFlag = (params.get("asymmetric") == null);
  } 
  
  private static void printUsage() {
    System.out.print("Usage:");
    System.out.println("\t\"KeyczarTool command flags\"");
    System.out.println("Commands:");
    System.out.println("\tcreate --name=name --location=location " + 
        "--purpose=purpose: Creates a new key store");
    System.out.println("\taddkey --location=location --status=status " + 
    ": Adds a new key to a store in the existing location.");
    System.out.println("Flags:");
    System.out.println("\t--name : Define the name of a keystore. Optional.");
    System.out.println("\t--location : Define the name of a keystore");
    System.out.println("\t--purpose : Define the purpose of a keystore. " + 
        "Must be sign, crypt, or test.");
    System.out.println("\t--status : Define the status of a new key. " + 
        "Must be primary, active, or scheduled_for_revocation. Optional.");
    
  }
}
