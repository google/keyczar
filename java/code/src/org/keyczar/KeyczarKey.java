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

package org.keyczar;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.keyczar.RsaPublicKey.Padding;
import org.keyczar.enums.KeyType;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.exceptions.UnsupportedTypeException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.Stream;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import com.google.gson.annotations.Expose;

/**
 * Common base wrapper class for different types of KeyczarKeys (e.g. AesKey).
 * Allows generating arbitrary key types or parsing key info from JSON
 * string representations. Binds each key to a hash identifier and exposes
 * the Stream used to access the key material.
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 *
 */
public abstract class KeyczarKey {
  private static final String PEM_FOOTER_BEGIN = "-----END ";
  private static final String PEM_LINE_ENDING = "-----\n";
  private static final String PEM_HEADER_BEGIN = "-----BEGIN ";

  @Expose final int size;

  private static final int PBE_SALT_SIZE = 8;
  private static final int IV_SIZE = 16;
  private static final int PBE_ITERATION_COUNT = 1000;

  // Note that SHA1 and 3DES appears to be the best PBE configuration supported by Sun's JCE.
  private static final String PBE_CIPHER = "PBEWithSHA1AndDESede";

  protected KeyczarKey(int size) {
    this.size = size;
  }

  void copyHeader(ByteBuffer dest) {
    dest.put(Keyczar.FORMAT_VERSION);
    dest.put(hash());
  }

  @Override
  public boolean equals(Object o) {
    try {
      KeyczarKey key = (KeyczarKey) o;
      return Arrays.equals(key.hash(), this.hash());
    } catch (ClassCastException e) {
      return false;
    }
  }

  @Override
  public int hashCode() {
    return Util.toInt(this.hash());
  }

  abstract Stream getStream() throws KeyczarException;

  /**
   * Return this key's type
   *
   * @return KeyType of this key
   */
  public abstract KeyType getType();

  /**
   * Return this key's hash value
   *
   * @return A byte array hash of this key material
   */
  abstract byte[] hash();

  int size() {
    return size;
  }

  /**
   * Generates private key of desired type and of the default size.
   *
   * @param type KeyType desired
   * @return KeyczarKey of desired type
   * @throws KeyczarException for unsupported key types
   */
  static KeyczarKey genKey(KeyType type) throws KeyczarException {
    return genKey(type, type.defaultSize());
  }

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  /**
   * Generates private key of the desired type and size. Cannot generate public
   * key, instead must export public key set from private keys.
   *
   * If given size is unacceptable, falls back to using default size for the
   * desired key type.
   *
   * @param type KeyType desired
   * @param keySize desired length of key
   * @return KeyczarKey of desired type
   * @throws KeyczarException for unsupported key types
   */
  static KeyczarKey genKey(KeyType type, int keySize) throws KeyczarException {
    Padding padding = null;
    if (type == KeyType.RSA_PRIV) {
      padding = Padding.OAEP;
    }
    return genKey(type, padding, keySize);
  }

  /**
   * Generates private key of the desired type and size. Cannot generate public
   * key, instead must export public key set from private keys.
   *
   * If given size is unacceptable, falls back to using default size for the
   * desired key type.
   *
   * @param type KeyType desired
   * @param padding Encryption padding type for RSA keys.  Should be null for others.
   * @param keySize desired length of key
   * @return KeyczarKey of desired type
   * @throws KeyczarException for unsupported key types
   */
  static KeyczarKey genKey(KeyType type, Padding padding, int keySize) throws KeyczarException {
    if (!type.isAcceptableSize(keySize)) {
      keySize = type.defaultSize();  // fall back to default
    }
    if (padding != null && type != KeyType.RSA_PRIV) {
      throw new KeyczarException(Messages.getString("InvalidPadding", padding.name()));
    }
    switch (type) {
      case AES:
        return AesKey.generate(keySize);
      case HMAC_SHA1:
        return HmacKey.generate(keySize);
      case DSA_PRIV:
        return DsaPrivateKey.generate(keySize);
      case RSA_PRIV:
        return RsaPrivateKey.generate(keySize, padding);
      // Currently unsupported. See "unofficial" directory.
      //case EC_PRIV:
      //    return EcPrivateKey.generate(keySize);
      case RSA_PUB: case DSA_PUB:
        throw new KeyczarException(
            Messages.getString("KeyczarKey.PublicKeyExport", type));
    }
    throw new UnsupportedTypeException(type);
  }

  /**
   * Converts a JSON string representation of a KeyczarKey into the appropriate
   * KeyczarKey object.
   *
   * @param type KeyType being read from JSON input
   * @param key JSON String representation of a KeyczarKey
   * @return KeyczareKey of given type
   * @throws KeyczarException if type mismatch with JSON input or unsupported
   * key type
   */
  static KeyczarKey readKey(KeyType type, String key) throws KeyczarException {
    switch (type) {
      case AES:
        return AesKey.read(key);
      case HMAC_SHA1:
        return HmacKey.read(key);
      case DSA_PRIV:
        return DsaPrivateKey.read(key);
      case DSA_PUB:
        return DsaPublicKey.read(key);
      case RSA_PRIV:
        return RsaPrivateKey.read(key);
      case RSA_PUB:
        return RsaPublicKey.read(key);
      // Currently unsupported. See "unofficial" directory.
      //case EC_PRIV:
      //    return EcPrivateKey.read(key);
      //case EC_PUB:
      //    return EcPublicKey.read(key);
    }

    throw new UnsupportedTypeException(type);
  }

  /**
   * Returns a PKCS8 PEM-format string containing the key information.
   *
   * @param passphrase Passphrase to use for encrypting private keys.
   * Required for private keys, must be null for public keys.
   * @return PEM-format key data.
   */
  public String getPemString(String passphrase) throws KeyczarException {
    if (isSecret()) {
      if (passphrase == null || passphrase.length() < 8) {
        throw new KeyczarException(Messages.getString("KeyczarTool.PassphraseRequired"));
      }
      return convertDerToPem(encryptPrivateKey(getJceKey(), passphrase));
    } else {
      if (passphrase != null && !"".equals(passphrase)) {
        throw new KeyczarException(Messages.getString("KeyczarTool.PassphraseNotAllowed"));
      }
      return convertDerToPem(getJceKey().getEncoded());
    }
  }

  private static byte[] encryptPrivateKey(Key key, String passphrase) throws KeyczarException {
    try {
      PBEKeySpec pbeSpec = new PBEKeySpec(passphrase.toCharArray());
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_CIPHER);
      Key pkcs8EncryptionKey = keyFactory.generateSecret(pbeSpec);

      byte[] salt = new byte[PBE_SALT_SIZE];
      Util.rand(salt);

      byte[] iv = new byte[IV_SIZE];
      Util.rand(iv);

      Cipher cipher = Cipher.getInstance(PBE_CIPHER);
      cipher.init(
          Cipher.ENCRYPT_MODE, pkcs8EncryptionKey, new PBEParameterSpec(salt, PBE_ITERATION_COUNT));
      byte[] encryptedKey = cipher.doFinal(key.getEncoded());
      EncryptedPrivateKeyInfo inf = new EncryptedPrivateKeyInfo(cipher.getParameters(), encryptedKey);
      return inf.getEncoded();
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(Messages.getString("KeyczarTool.FailedToEncryptPrivateKey"), e);
    } catch (IOException e) {
      // This should be impossible.
      throw new KeyczarException(Messages.getString("KeyczarTool.FailedToEncryptPrivateKey"), e);
    }
  }

  private String convertDerToPem(final byte[] keyData) {
    String base64Key = Base64Coder.encodeMime(keyData, true);
    StringBuffer result = new StringBuffer();
    result.append(PEM_HEADER_BEGIN);
    result.append(getPemType());
    result.append(PEM_LINE_ENDING);
    for (String line : Util.split(base64Key, 64)) {
      result.append(line);
      result.append('\n');
    }
    result.append(PEM_FOOTER_BEGIN);
    result.append(getPemType());
    result.append(PEM_LINE_ENDING);

    return result.toString();
  }

  protected boolean isSecret() {
    return true;
  }

  abstract protected Key getJceKey();

  private String getPemType() {
    if (isSecret()) {
      return "ENCRYPTED PRIVATE KEY";
    } else {
      return getJceKey().getAlgorithm() + " PUBLIC KEY";
    }
  }
}
