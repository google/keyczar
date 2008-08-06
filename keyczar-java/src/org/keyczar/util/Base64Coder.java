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


import org.keyczar.exceptions.Base64DecodingException;
import org.keyczar.i18n.Messages;

/**
 * A web-safe Base64 encoding and decoding utility class. See RFC 3548
 *
 * @author steveweis@gmail.com (Steve Weis)
 *
 */
public class Base64Coder {
  /**
   * Mapping table from 6-bit nibbles to Base64 characters.
   */
  private static final char[] ALPHABET = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
      'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
      'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
      'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '-', '_'};
  /**
   * Mapping table from Base64 characters to 6-bit nibbles.
   */
  private static final byte[] DECODE = new byte[128];
  private static final char[] WHITESPACE = {'\t', '\n', '\r', ' ', '\f'};

  static {
    for (int i = 0; i < DECODE.length; i++) {
      DECODE[i] = -1;
    }

    for (int i = 0; i < WHITESPACE.length; i++) {
      DECODE[WHITESPACE[i]] = -2;
    }

    for (int i = 0; i < ALPHABET.length; i++) {
      DECODE[ALPHABET[i]] = (byte) i;
    }
  }

  private Base64Coder() {
    // Don't new me.
  }

  /**
   * Decodes a web-safe Base64 encoded string
   * @param source The string to decode. May contain whitespace and optionally
   * up to two padding '=' characters.
   * @return A byte array representation of the encoded data.
   * @throws Base64DecodingException If the source string contains an illegal
   * character or is of an illegal length (1 mod 4).
   */
  public static byte[] decode(String source) throws Base64DecodingException {
    char[] input = source.toCharArray();
    int inLen = input.length;
    // Trim up to two trailing '=' padding characters
    if (input[inLen - 1] == '=') {
      inLen--;
    }
    if (input[inLen - 1] == '=') {
      inLen--;
    }

    // Ignore whitespace
    int whiteSpaceChars = 0;
    for (char c : input) {
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
      throw new Base64DecodingException(
          Messages.getString("Base64Coder.IllegalLength", inLen));
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
      if (!isWhiteSpace(input[i])) {
        buffer = (buffer << 6) | getByte(input[i]);
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
    switch (buffCount) {
    case 2:
      out[outPos++] = (byte) (buffer >> 4);
      break;
    case 3:
      out[outPos++] = (byte) (buffer >> 10);
      out[outPos++] = (byte) (buffer >> 2);
      break;
    }
    return out;
  }

  /**
   * Encodes an arbitrary array of input as a web-safe Base64 string.
   * @param input Input bytes to encode as a web-safe Base64 String
   * @return A web-safe Base64 representation of the input. This string will not
   * be padded with '=' characters.
   */
  public static String encode(byte[] input) {
    int inputBlocks = input.length / 3;
    int remainder = input.length % 3;
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
      int buffer = (0xFF & input[inPos++]) << 16 | (0xFF & input[inPos++]) << 8
          | (0xFF & input[inPos++]);
      out[outPos++] = ALPHABET[(buffer >> 18) & 0x3F];
      out[outPos++] = ALPHABET[(buffer >> 12) & 0x3F];
      out[outPos++] = ALPHABET[(buffer >> 6) & 0x3F];
      out[outPos++] = ALPHABET[buffer & 0x3F];
    }

    if (remainder > 0) {
      int buffer = (0xFF & input[inPos++]) << 16;
      if (remainder == 2) {
        buffer |= (0xFF & input[inPos++]) << 8;
      }
      out[outPos++] = ALPHABET[(buffer >> 18) & 0x3F];
      out[outPos++] = ALPHABET[(buffer >> 12) & 0x3F];
      if (remainder == 2) {
        out[outPos++] = ALPHABET[(buffer >> 6) & 0x3F];
      }
    }
    return new String(out);
  }

  private static byte getByte(int i) throws Base64DecodingException {
    if (i < 0 || i > 127 || DECODE[i] == -1) {
      throw new Base64DecodingException(
          Messages.getString("Base64Coder.IllegalCharacter", i));
    }
    return DECODE[i];
  }

  private static boolean isWhiteSpace(int i) {
    return DECODE[i] == -2;
  }
}