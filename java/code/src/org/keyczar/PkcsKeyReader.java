/*
 * Copyright 2011 Google Inc.
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

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.i18n.Messages;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Keyczar Reader that reads from a PKCS#8 private key file, optionally
 * passphrase-encrypted.
 *
 * @author swillden@google.com (Shawn Willden)
 */
public class PkcsKeyReader implements KeyczarReader {
  private static final Pattern PEM_HEADER_PATTERN = Pattern.compile("-----BEGIN ([A-Z ]+)-----");
  private static final Pattern PEM_FOOTER_PATTERN = Pattern.compile("-----END ([A-Z ]+)-----");
  private final KeyPurpose purpose;
  private final InputStream pkcs8Stream;
  private final RsaPadding rsaPadding;
  private final String passphrase;
  private KeyMetadata meta;
  private KeyczarKey key;

  /**
   * Creates a PkcsKeyReader.
   *
   * @param purpose The purpose that will be specified for this key.  PKCS#8 doesn't specify
   *        a purpose, so it must be provided.
   * @param pkcs8Stream The input stream from which the PKCS#8-formatted key data will be read.
   * @param rsaPadding If the PKCS#8 stream contains an RSA key, padding may be specified.  If
   *        null, OAEP will be assumed.  If the stream contains a DSA key, padding must be null.
   * @param passphrase The passphrase that will be used to decrypt the encrypted private key.  If
   *        the key is not encrypted, this should be null or the empty string.
   */
  public PkcsKeyReader(KeyPurpose purpose, InputStream pkcs8Stream, RsaPadding rsaPadding,
      String passphrase) throws KeyczarException {
    if (purpose == null) {
      throw new KeyczarException("Key purpose must not be null");
	}
	if (pkcs8Stream == null) {
	  throw new KeyczarException("PKCS8 stream must not be null");
	}
    this.purpose = purpose;
    this.pkcs8Stream = pkcs8Stream;
    this.rsaPadding = rsaPadding;
    this.passphrase = passphrase;
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    ensureKeyRead();
    return key.toString();
  }

  @Override
  public String getKey() throws KeyczarException {
    ensureKeyRead();
    return key.toString();
  }

  @Override
  public String getMetadata() throws KeyczarException {
    ensureKeyRead();
    return meta.toString();
  }

  private void ensureKeyRead() throws KeyczarException {
    try {
      if (key == null) {
        key = parseKeyStream(pkcs8Stream, passphrase, rsaPadding);
        meta = constructMetadata(key, purpose);
      }
    } catch (IOException e) {
      throw new KeyczarException("Error Reading key", e);
    }
  }

  private static KeyMetadata constructMetadata(KeyczarKey key, KeyPurpose purpose)
      throws KeyczarException {
    validatePurpose(key, purpose);
    KeyMetadata meta = new KeyMetadata("imported from PKCS8 file", purpose, key.getType());
    meta.addVersion(new KeyVersion(1, KeyStatus.PRIMARY, true /* exportable */));
    return meta;
  }

  private static void validatePurpose(KeyczarKey key, KeyPurpose purpose) throws KeyczarException {
    if (purpose == KeyPurpose.ENCRYPT && key.getType() == DefaultKeyType.DSA_PUB) {
      throw new KeyczarException(Messages.getString("Keyczartool.InvalidUseOfDsaKey"));
    }
  }

  private static KeyczarKey parseKeyStream(InputStream pkcs8Stream, String passphrase,
      RsaPadding padding) throws IOException, KeyczarException {
    byte[] pkcs8Data = convertPemToDer(Util.readStreamFully(pkcs8Stream));
    pkcs8Data = decryptPbeEncryptedKey(pkcs8Data, passphrase);

    PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(pkcs8Data);

    // There's no way to ask the kspec what type of key it contains, so we have to try each
    // type in turn.
    try {
      return new RsaPrivateKey(
        (RSAPrivateCrtKey) PkcsKeyReader.extractPrivateKey(kspec, "RSA"), padding);
    } catch (InvalidKeySpecException e) {
      // Not a valid RSA key, fall through.
    }

    try {
      KeyczarKey key = new DsaPrivateKey(
        (DSAPrivateKey) PkcsKeyReader.extractPrivateKey(kspec, "DSA"));
      if (padding != null) {
        throw new KeyczarException(Messages.getString("InvalidPadding", padding.name()));
      }
      return key;
    } catch (InvalidKeySpecException e) {
      //Not a valid DSA key, fall through.
    }

    throw new KeyczarException(Messages.getString("KeyczarTool.InvalidPkcs8Stream"));
  }

  private static PrivateKey extractPrivateKey(PKCS8EncodedKeySpec kspec, String algorithm)
      throws KeyczarException, InvalidKeySpecException {
    try {
      return KeyFactory.getInstance(algorithm).generatePrivate(kspec);
    } catch (NoSuchAlgorithmException e) {
      throw new KeyczarException(e);
    }
  }

  private static byte[] decryptPbeEncryptedKey(final byte[] pkcs8Data, final String passphrase)
      throws KeyczarException {
    if (passphrase == null || passphrase.length() == 0) {
      return pkcs8Data;
    }

    try {
      final EncryptedPrivateKeyInfo encryptedKeyInfo = new EncryptedPrivateKeyInfo(pkcs8Data);
      final PBEParameterSpec pbeParamSpec =
          encryptedKeyInfo.getAlgParameters().getParameterSpec(PBEParameterSpec.class);
      final String algName = encryptedKeyInfo.getAlgName();
      final Cipher pbeCipher = Cipher.getInstance(algName);
      pbeCipher.init(Cipher.DECRYPT_MODE, computeDecryptionKey(passphrase, algName), pbeParamSpec);
      return pbeCipher.doFinal(encryptedKeyInfo.getEncryptedData());
    } catch (NullPointerException e) {
      throw new KeyczarException(Messages.getString("KeyczarTool.UnknownKeyEncryption"));
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(Messages.getString("KeyczarTool.UnknownKeyEncryption"));
    } catch (IOException e) {
      throw new KeyczarException(Messages.getString("KeyczarTool.UnknownKeyEncryption"));
    }
  }

  private static SecretKey computeDecryptionKey(final String passphrase,
      final String pbeAlgorithmName) throws NoSuchAlgorithmException, InvalidKeySpecException {
    final PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase.toCharArray());
    final SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pbeAlgorithmName);
    return pbeKeyFactory.generateSecret(pbeKeySpec);
  }

  private static byte[] convertPemToDer(byte[] data) throws IOException, KeyczarException {
    BufferedReader bis = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
    String firstLine = bis.readLine();
    Matcher headerMatcher = PEM_HEADER_PATTERN.matcher(firstLine);
    if (!headerMatcher.matches()) {
      // No properly-formatted header?  Assume it's DER format.
      return data;
    } else {
      String header = headerMatcher.group(1);
      return decodeBase64(bis, header);
    }
  }

  private static byte[] decodeBase64(BufferedReader inputStream, String expectedFooter)
      throws IOException, KeyczarException {
    String line;
    ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
    while ((line = inputStream.readLine()) != null) {
      Matcher footerMatcher = PEM_FOOTER_PATTERN.matcher(line);
      if (!footerMatcher.matches()) {
        tempStream.write(Base64Coder.decodeMime(line));
      } else if (footerMatcher.group(1).equals(expectedFooter)) {
        return tempStream.toByteArray();
      } else {
        break;
      }
    }
    throw new KeyczarException(Messages.getString("KeyczarTool.InvalidPemFile"));
  }
}
