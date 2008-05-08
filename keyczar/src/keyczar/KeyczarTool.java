// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import keyczar.internal.DataPacker;
import keyczar.internal.DataPackingException;
import keyczar.internal.DataUnpacker;

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
  
  private static void addKey() throws KeyczarException {
    // Read existing metadata
    if (locationFlag == null) {
      throw new KeyczarException("Must define a key set location with the " +
          "--location flag");
    }
    Keyczar keyczar = new Keyczar(new KeyczarFileReader(locationFlag));
    keyczar.read();
    keyczar.addVersion(statusFlag);
    KeyczarFileWriter.writeKeyczar(locationFlag, keyczar);
  }
  
  private static void create() throws KeyczarException,
      DataPackingException {
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
    Keyczar dummy = new Keyczar(locationFlag);
    dummy.setMetadata(kmd);
    KeyczarFileWriter.writeKeyczar(locationFlag, dummy);
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
    // TODO: Fill in a usage message
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
