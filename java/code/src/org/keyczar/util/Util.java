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

package org.keyczar.util;

import org.json.JSONException;
import org.json.JSONObject;
import org.keyczar.exceptions.Base64DecodingException;
import org.keyczar.exceptions.KeyczarException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * A miscellaneous utility class. Includes random number generation, int-to-byte
 * conversion, etc.
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Util {
  private static final ConcurrentLinkedQueue<MessageDigest> DIGEST_QUEUE =
    new ConcurrentLinkedQueue<MessageDigest>();
  private static final ConcurrentLinkedQueue<SecureRandom> RAND_QUEUE =
    new ConcurrentLinkedQueue<SecureRandom>();
  private static final int READ_BUF_SIZE = 8192;

  private Util() {
    // Don't new me.
  }

  public static byte[] stripLeadingZeros(byte[] input) {
    int zeros = 0;

    // Find the first non-zero byte
    while (zeros < input.length && input[zeros] == 0) {
      zeros++;
    }

    if (zeros == 0) {
      return input;
    } else {
      byte[] output = new byte[input.length - zeros];
      System.arraycopy(input, zeros, output, 0, output.length);
      return output;
    }
  }

  /**
   * Returns a byte array containing 4 big-endian ordered bytes representing the
   * given integer.
   *
   * @param input The integer to convert to a byte array.
   * @return A byte array representation of an integer.
   */
  public static byte[] fromInt(int input) {
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
  public static byte[] fromLong(long input) {
    byte[] output = new byte[8];
    writeLong(input, output, 0);
    return output;
  }

  /**
   * Takes a variable number of byte arrays as input and hashes each one
   * prefixed by an integer representation of its size. For example,
   * prefixHash({0, 1, 2}, {1}) would hash the bytes equivalent to:
   * {3, 0, 1, 2, 1, 1}
   *
   * @param inputs The inputs to hash
   * @return The hash output
   * @throws KeyczarException If the SHA-1 algorithm is not found
   */
  public static byte[] prefixHash(byte[]... inputs) throws KeyczarException {
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

  /**
   * Prefixes an input array with a 4-byte transportable length field.
   * If the input data is null or has zero length, returns a 4-byte
   * representation of 0.
   *
   * @param data
   * @return The input data prefixed by a 4-byte representation of its length
   */
  public static byte[] lenPrefix(byte[] data) {
    if (data == null || data.length == 0) {
      return fromInt(0);
    }
    return ByteBuffer.allocate(4 + data.length)
        .putInt(data.length)
        .put(data)
        .array();
  }

  /**
   * Packs a set of input arrays into a single array. The packed array is
   * prefixed by an integer value of the number of arrays. Then each individual
   * array is prefixed by its length, followed by the contents of the array
   * itself. Thus, three arrays A, B, C would output:
   *   {3, len(A), A, len(B), B, len(C), C}
   *
   * @param inputArrays A list of arrays to pack together
   * @return A packed list of arrays, with each preceded by its integer length
   */
  public static byte[] lenPrefixPack(byte[]... inputArrays) {
    // Count an int for each input array
    int outputSize = (1 + inputArrays.length) * 4;
    for (byte[] array : inputArrays) {
      outputSize += array.length;
    }
    byte[] output = new byte[outputSize];
    ByteBuffer outputBuffer = ByteBuffer.wrap(output);
    // Put the number of total arrays
    outputBuffer.putInt(inputArrays.length);
    for (byte[] array : inputArrays) {
      // Put the size of this array
      outputBuffer.putInt(array.length);
      // Put the array itself
      outputBuffer.put(array);
    }
    return output;
  }

  /**
   * Unpack an input buffer into an array of byte arrays
   *
   * @param packedInput A packed representation of an array of byte arrays
   * @param maxLength The max number of byte arrays allowed.
   * @return A two dimensional array of arrays, null if length prefix is not less than maxLength
   */
  public static byte[][] lenPrefixUnpack(byte[] packedInput, int maxArrays) {
    ByteBuffer input = ByteBuffer.wrap(packedInput);
    int numArrays = input.getInt();
    if (numArrays < 0 || numArrays > maxArrays) {
      return null;
    }
    byte[][] output = new byte[numArrays][];
    for (int i = 0; i < numArrays; i++) {
      if (input.remaining() < 4) {
        return null;
      }
      int len = input.getInt();
      if (len < 0 || len > input.remaining()) {
        return null;
      }
      byte[] array = new byte[len];
      input.get(array);
      output[i] = array;
    }
    return output;
  }

  /**
   * Hashes a variable number of byte arrays
   *
   * @param inputs The inputs to hash
   * @return The hash output
   * @throws KeyczarException If the SHA-1 algorithm is not found
   */
  public static byte[] hash(byte[]... inputs) throws KeyczarException {
    MessageDigest md = DIGEST_QUEUE.poll();
    if (md == null) {
      try {
        md = MessageDigest.getInstance("SHA-1");
      } catch (NoSuchAlgorithmException e) {
        throw new KeyczarException(e);
      }
    }
    for (byte[] array : inputs) {
      md.update(array);
    }
    byte[] digest = md.digest();
    DIGEST_QUEUE.add(md);
    return digest;
  }

  /**
   * Write random bytes into the destination. Uses pre-cached secure random
   * objects
   *
   * @param dest Destination to write the data
   */
  public static void rand(byte[] dest) {
    SecureRandom random = RAND_QUEUE.poll();
    if (random == null) {
      random = new SecureRandom();
    }
    random.nextBytes(dest);
    RAND_QUEUE.add(random);
  }

  /**
   * Returns an array of random bytes of the given length
   * @param len The length of the random array to output
   * @return A random array of bytes
   */
  public static byte[] rand(int len) {
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
  public static int toInt(byte[] src) {
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
  public static long toLong(byte[] src) {
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

  /**
   * An array comparison that is safe from timing attacks. If two arrays are
   * of equal length, this code will always check all elements, rather than
   * exiting once it encounters a differing byte.
   *
   * @param a1 An array to compare
   * @param a2 Another array to compare
   * @return True if these arrays are both null or if they have equal length
   *         and equal bytes in all elements
   */
  public static boolean safeArrayEquals(byte[] a1, byte[] a2) {
    if (a1 == null || a2 == null) {
        return (a1 == a2);
    }
    if (a1.length != a2.length) {
      return false;
    }
    byte result = 0;
    for (int i = 0; i < a1.length; i++) {
      result |= a1[i] ^ a2[i];
    }
    return (result == 0);
  }

  /**
   * Concatenate arrays together.
   *
   * @param arrays byte[] arrays to combine
   * @return single byte[] with all the data combined.
   */
  public static byte[] cat(byte[]... arrays) {
    int length = 0;
    for (byte[] array : arrays) {
      length += array.length;
    }
    byte[] result = new byte[length];
    int pos = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, pos, array.length);
      pos += array.length;
    }
    return result;
  }

  /**
   * Splits a string into chunks of specified size.
   */
  public static List<String> split(String s, int chunkSize) {
    List<String> chunks = new ArrayList<String>();
    int length = s.length();
    for (int i = 0; i < length; i += chunkSize) {
      chunks.add(s.substring(i, Math.min(length, i + chunkSize)));
    }
    return chunks;
  }

  /**
   * Reads all data from the provided stream into memory and returns it as a byte array.
   */
  public static byte[] readStreamFully(InputStream inStream) throws IOException {
    ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
    byte[] buf = new byte[Util.READ_BUF_SIZE];
    int bytesRead = 0;
    while ((bytesRead = inStream.read(buf)) != -1) {
      tempStream.write(buf, 0, bytesRead);
    }
    return tempStream.toByteArray();
  }

  /**
   * Web safe Base64-encode a BigInteger.
   */
  public static String encodeBigInteger(BigInteger value) {
    return Base64Coder.encodeWebSafe(value.toByteArray());
  }

  /**
   * Web safe Base64-decode a BigInteger.
   */
  public static BigInteger decodeBigInteger(String value) throws Base64DecodingException {
    return new BigInteger(Base64Coder.decodeWebSafe(value));
  }

  /**
   * Generate a public/private key pair with the specified algorithm and key size.
   */
  public static KeyPair generateKeyPair(String algorithm, int keySize)
      throws KeyczarException {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
      kpg.initialize(keySize);
      KeyPair pair = kpg.generateKeyPair();
      return pair;
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  public static <T extends Enum<T>> T deserializeEnum(Class<T> enumType, String name) {
    if (name == null || name.isEmpty()) {
      return null;
    }
    return Enum.valueOf(enumType, name);
  }

  public static Map<String, String> deserializeMap(JSONObject jsonObject)
      throws JSONException {
    Map<String, String> map = new HashMap<String, String>();
    if (jsonObject != null) {
      Iterator<String> iter = jsonObject.keys();
      while (iter.hasNext()) {
        String key = iter.next();
        String value = jsonObject.getString(key);
        map.put(key,  value);
      }
    }
    return map;
  }
}
