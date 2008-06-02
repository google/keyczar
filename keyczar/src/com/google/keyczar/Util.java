// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.keyczar.exceptions.Base64DecodingException;
import com.google.keyczar.exceptions.KeyczarException;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentLinkedQueue;


/**
 * 
 * @author sweis@google.com (Your Name Here)
 * 
 */
class Util {
  private static final ConcurrentLinkedQueue<MessageDigest> DIGEST_QUEUE = 
    new ConcurrentLinkedQueue<MessageDigest>();
  private static final ConcurrentLinkedQueue<SecureRandom> RAND_QUEUE = 
    new ConcurrentLinkedQueue<SecureRandom>();
  
  /**
   * Mapping table from 6-bit nibbles to Base64 characters.
   */
  private static char[] ALPHABET = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
      'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
      'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
      'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '-', '_'};
  /**
   * Mapping table from Base64 characters to 6-bit nibbles.
   */
  private static byte[] DECODE = new byte[128];
  private static final Gson gson = new GsonBuilder()
      .excludeFieldsWithoutExposeAnnotation().create();

  private static char[] WHITESPACE = {'\t', '\n', '\r', ' ', '\f'};

  static {
    for (int i = 0; i < DECODE.length; i++) {
      DECODE[i] = -1;
    }

    for (int i = 0; i < WHITESPACE.length; i++) {
      DECODE[WHITESPACE[i]] = -2;
    }

    for (int i = 0; i < 64; i++) {
      DECODE[ALPHABET[i]] = (byte) i;
    }
  }

  private Util() {
    // Don't new me.
  }

  // TODO: Write JavaDocs
  static byte[] base64Decode(String src) throws Base64DecodingException {
    char[] in = src.toCharArray();
    int inLen = in.length;
    // Trim up to two trailing '=' padding characters
    if (in[inLen - 1] == '=') {
      inLen--;
    }
    if (in[inLen - 1] == '=') {
      inLen--;
    }

    // Ignore whitespace
    int whiteSpaceChars = 0;
    for (char c : in) {
      if (isWhiteSpace(c)) {
        whiteSpaceChars++;
      }
    }

    inLen -= whiteSpaceChars;
    int inputBlocks = inLen / 4;
    int remainder = inLen % 4;
    int outputLen = inputBlocks * 3;
    switch (remainder) {
    case 1:
      throw new Base64DecodingException("Input source is of illegal length");
    case 2:
      outputLen += 1;
      break;
    case 3:
      outputLen += 2;
      break;
    }
    byte[] out = new byte[outputLen];
    int buffer = 0;
    int buffCount = 0;
    int outPos = 0;
    for (int i = 0; i < inLen + whiteSpaceChars; i++) {
      if (!isWhiteSpace(in[i])) {
        buffer = (buffer << 6) | getByte(in[i]);
        buffCount++;
      }
      if (buffCount == 4) {
        out[outPos++] = (byte) (buffer >> 16);
        out[outPos++] = (byte) (buffer >> 8);
        out[outPos++] = (byte) buffer;
        buffer = 0;
        buffCount = 0;
      }
    }
    if (buffCount != remainder) {
      throw new Base64DecodingException("Buffer is not of the expected size");
    }
    switch (buffCount) {
    case 2:
      out[outPos++] = (byte) (buffer >> 4);
      break;
    case 3:
      out[outPos++] = (byte) (buffer >> 10);
      out[outPos++] = (byte) (buffer >> 2);
      break;
    }

    if (outPos != out.length) {
      throw new Base64DecodingException("Wrong output size");
    }
    return out;
  }

  // TODO: Write JavaDocs
  static String base64Encode(byte[] in) {
    int inputBlocks = in.length / 3;
    int remainder = in.length % 3;
    int outputLen = inputBlocks * 4;

    switch (remainder) {
    case 1:
      outputLen += 2;
      break;
    case 2:
      outputLen += 3;
      break;
    }

    char[] out = new char[outputLen];
    int outPos = 0;
    int inPos = 0;

    for (int i = 0; i < inputBlocks; i++) {
      int buffer = (0xFF & in[inPos++]) << 16 | (0xFF & in[inPos++]) << 8
          | (0xFF & in[inPos++]);
      out[outPos++] = ALPHABET[(buffer >> 18) & 0x3F];
      out[outPos++] = ALPHABET[(buffer >> 12) & 0x3F];
      out[outPos++] = ALPHABET[(buffer >> 6) & 0x3F];
      out[outPos++] = ALPHABET[buffer & 0x3F];
    }

    if (remainder > 0) {
      int buffer = in[inPos++] << 16;
      if (remainder == 2) {
        buffer |= in[inPos++] << 8;
      }
      out[outPos++] = ALPHABET[(buffer >> 18) & 0x3F];
      out[outPos++] = ALPHABET[(buffer >> 12) & 0x3F];
      if (remainder == 2) {
        out[outPos++] = ALPHABET[(buffer >> 6) & 0x3F];
      }
    }
    return new String(out);
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

  static Gson gson() {
    return gson;
  }

  /**
   * Hashes a variable number of inputs and returns a new byte array
   * 
   * @param inputs The inputs to hash
   * @return The hash output
   * @throws KeyczarException If the SHA-1 algorithm is not found 
   */
  static byte[] prefixHash(byte[]... inputs) throws KeyczarException {
    MessageDigest md = DIGEST_QUEUE.poll();
    if (md == null) {
      try {
        md = MessageDigest.getInstance("SHA-1");
      } catch (NoSuchAlgorithmException e) {
        throw new KeyczarException(e);
      }
    }
    for (byte[] array : inputs) {
      md.update(fromInt(array.length));
      md.update(array);
    }
    byte[] digest = md.digest();
    DIGEST_QUEUE.add(md);
    return digest;
  }

  // TODO: Write JavaDocs
  static void rand(byte[] dest) {
    SecureRandom random = RAND_QUEUE.poll();
    if (random == null) {
      random = new SecureRandom();
    }
    random.nextBytes(dest);
    RAND_QUEUE.poll();
  }

  // TODO: Write JavaDocs
  static byte[] rand(int len) {
    byte[] output = new byte[len];
    rand(output);
    return output;
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

  /**
   * Converts a given byte array to an integer. Reads the bytes in big-endian
   * order.
   * 
   * This method does not check the source array length.
   * 
   * @param src A big-endian representation of an integer
   * @return The integer value represented by the source array
   */
  static int toInt(byte[] src) {
    return readInt(src, 0);
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

  private static byte getByte(int i) throws Base64DecodingException {
    if (i < 0 || i > 127 || DECODE[i] == -1) {
      throw new Base64DecodingException("Illegal character in Base64 string");
    }
    return DECODE[i];
  }

  private static boolean isWhiteSpace(int i) {
    return DECODE[i] == -2;
  }
}
