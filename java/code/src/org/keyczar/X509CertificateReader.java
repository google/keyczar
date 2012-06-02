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

import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author swillden@google.com (Shawn Willden)
 */
public class X509CertificateReader implements KeyczarReader {
  private final InputStream certificateStream;
  private final KeyPurpose purpose;
  private final RsaPadding padding;
  private KeyMetadata meta = null;
  private KeyczarPublicKey key;

  /**
   * Creates an certificate reader that reads a key from the specified stream, tags it with the
   * specified purpose and sets it to use the specified padding.
   *
   * @param padding The padding to associate with the key.  May be null for RSA keys, in
   * which case it will default to OAEP.  Must be null for DSA keys.
   * @throws KeyczarException
   */
  public X509CertificateReader(KeyPurpose purpose, InputStream certificateStream, RsaPadding padding)
      throws KeyczarException {
    if (purpose == null) {
      throw new KeyczarException("X509Certificate purpose must not be null");
	}
	if (certificateStream == null) {
	  throw new KeyczarException("X509Certificate stream must not be null");
	}
    this.purpose = purpose;
    this.certificateStream = certificateStream;
    this.padding = padding;
  }

  @Override
  public String getKey(int version) throws KeyczarException {
    ensureCertificateRead();
    return key.toString();
  }

  @Override
  public String getKey() throws KeyczarException {
    ensureCertificateRead();
    return key.toString();
  }

  @Override
  public String getMetadata() throws KeyczarException {
    ensureCertificateRead();
    return meta.toString();
  }

  private void ensureCertificateRead() throws KeyczarException {
    if (key == null) {
      try {
        parseCertificate();
        constructMetadata();
      } catch (CertificateException e) {
        throw new KeyczarException(Messages.getString("KeyczarTool.InvalidCertificate"), e);
      }
    }
  }

  private void constructMetadata() throws KeyczarException {
    if (purpose == KeyPurpose.ENCRYPT && key.getType() == DefaultKeyType.DSA_PUB) {
      throw new KeyczarException(Messages.getString("Keyczartool.InvalidUseOfDsaKey"));
    }
    meta = new KeyMetadata("imported from certificate", purpose, key.getType());
    meta.addVersion(new KeyVersion(1, KeyStatus.PRIMARY, true /* exportable */));
  }

  private void parseCertificate() throws CertificateException, KeyczarException {
    Certificate certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(certificateStream);
    PublicKey publicKey = certificate.getPublicKey();

    if (publicKey instanceof RSAPublicKey) {
      key = new RsaPublicKey((RSAPublicKey) publicKey, padding);
    } else if (publicKey instanceof DSAPublicKey) {
      if (padding != null) {
        throw new KeyczarException(Messages.getString("InvalidPadding", padding.name()));
      }
      key = new DsaPublicKey((DSAPublicKey) publicKey);
    } else {
      throw new KeyczarException("Unrecognized key type " + publicKey.getAlgorithm() +
          " in certificate");
    }
  }
}
