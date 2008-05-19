package keyczar;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * 
 * @author sweis@google.com (Your Name Here)
 * 
 */
class Util {
  private static MessageDigest md;
  private static SecureRandom random;
  private static final Gson gson =
    new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
  
  static {
    random = new SecureRandom();
    try {
      md = MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private Util() {
    // Don't new me.
  }
  
  static Gson gson() {
    return gson;
  }
  
  static void checkHashPrefix(byte[] hash, String encoded)
      throws KeyczarException {
    byte[] decoded = Util.base64Decode(encoded);
    byte[] fullHash = Util.prefixHash(decoded);
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Hash does not match");
      }
    }
  }
  

  // TODO: Write JavaDocs
  static synchronized byte[] rand(int len) {
    byte[] output = new byte[len];
    rand(output);
    return output;
  }
  
  // TODO: Write JavaDocs
  static synchronized void rand(byte[] dest) {
    random.nextBytes(dest);
  }
  
  /**
   * Hashes a variable number of inputs and returns a new byte array
   * 
   * @param inputs The inputs to hash
   * @return The hash output
   */
  static synchronized byte[] prefixHash(byte[]... inputs) {
    for (byte[] array : inputs) {
      md.update(fromInt(array.length));
      md.update(array);
    }
    return md.digest();
  }

  /**
   * Returns a byte array containing 4 big-endian ordered bytes representing the
   * given integer.
   * 
   * @param input The integer to convert to a byte array.
   * @return A byte array representation of an integer.
   */
  static byte[] fromInt(int input) {
    byte[] output = new byte[4];
    writeInt(input, output, 0);
    return output;
  }

  /**
   * Writes 4 big-endian ordered bytes representing the given integer into the
   * destination byte array starting from the given offset.
   * 
   * This method does not check the destination array length.
   * 
   * @param input The integer to convert to bytes
   * @param dest The array in which to write the integer byte representation
   * @param offset The offset to start writing the bytes from
   */
  static void writeInt(int input, byte[] dest, int offset) {
    dest[offset++] = (byte) (input >> 24);
    dest[offset++] = (byte) (input >> 16);
    dest[offset++] = (byte) (input >> 8);
    dest[offset++] = (byte) (input);
  }

  /**
   * Converts a given byte array to an integer. Reads the bytes in big-endian
   * order.
   * 
   * This method does not check the source array length.
   * 
   * @param src A big-endian representation of an integer
   * @return The integer value represented by the source array
   */
  public static int toInt(byte[] src) {
    return readInt(src, 0);
  }

  /**
   * Reads 4 big-endian ordered bytes from a given offset in an array and
   * returns an integer representation.
   * 
   * This method does not check the source array length.
   * 
   * @param src The source array to read bytes from
   * @param offset The offset to start reading bytes from.
   * @return The integer value represented by the source array from the offset
   */
  static int readInt(byte[] src, int offset) {
    int output = 0;
    output |= (src[offset++] & 0xFF) << 24;
    output |= (src[offset++] & 0xFF) << 16;
    output |= (src[offset++] & 0xFF) << 8;
    output |= (src[offset++] & 0xFF);
    return output;
  }

  /**
   * Returns a byte array containing 8 big-endian ordered bytes representing the
   * given long.
   * 
   * @param input The long to convert to a byte array.
   * @return A byte array representation of a long.
   */
  static byte[] fromLong(long input) {
    byte[] output = new byte[8];
    writeLong(input, output, 0);
    return output;
  }

  /**
   * Writes 8 big-endian ordered bytes representing the given long into the
   * destination byte array starting from the given offset.
   * 
   * This method does not check the destination array length.
   * 
   * @param input The long to convert to bytes
   * @param dest The array in which to write the long byte representation
   * @param offset The offset to start writing the bytes from
   */
  static void writeLong(long input, byte[] dest, int offset) {
    dest[offset++] = (byte) (input >> 56);
    dest[offset++] = (byte) (input >> 48);
    dest[offset++] = (byte) (input >> 40);
    dest[offset++] = (byte) (input >> 32);
    dest[offset++] = (byte) (input >> 24);
    dest[offset++] = (byte) (input >> 16);
    dest[offset++] = (byte) (input >> 8);
    dest[offset++] = (byte) (input);
  }

  /**
   * Converts a given byte array to a long. Reads the bytes in big-endian order.
   * 
   * This method does not check the source array length.
   * 
   * @param src A big-endian representation of a long
   * @return The long value represented by the source array
   */
  static long toLong(byte[] src) {
    return readLong(src, 0);
  }

  /**
   * Reads 8 big-endian ordered bytes from a given offset in an array and
   * returns a long representation.
   * 
   * This method does not check the source array length.
   * 
   * @param src The source array to read bytes from
   * @param offset The offset to start reading bytes from.
   * @return The long value represented by the source array from the offset
   */
  static long readLong(byte[] src, int offset) {
    long output = 0;
    output |= (src[offset++] & 0xFFL) << 56;
    output |= (src[offset++] & 0xFFL) << 48;
    output |= (src[offset++] & 0xFFL) << 40;
    output |= (src[offset++] & 0xFFL) << 32;
    output |= (src[offset++] & 0xFFL) << 24;
    output |= (src[offset++] & 0xFFL) << 16;
    output |= (src[offset++] & 0xFFL) << 8;
    output |= (src[offset++] & 0xFFL);
    return output;
  }
  
  // TODO: Write JavaDocs
  static String base64Encode(byte[] src) {
    // TODO: Use standard Base64 encoder 
    // Blatent misuse of sun.misc package. This could change at any time.
    return new sun.misc.BASE64Encoder().encode(src);
  }
  
  // TODO: Write JavaDocs
  static byte[] base64Decode(String src) throws KeyczarException {
    // TODO: Use standard Base64 decoder
    // Blatent misuse of sun.misc package. This could change at any time.
    try {
      return new sun.misc.BASE64Decoder().decodeBuffer(src);
    } catch (IOException e) {
      throw new KeyczarException(e);
    }
  }
}
