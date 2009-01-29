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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.keyczar.exceptions.KeyczarException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

  private Util() {
    // Don't new me.
  }

  private static final Gson GSON =
    new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();

  public static Gson gson() {
    return GSON;
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
   * @param dest Destionation to write the data
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
}