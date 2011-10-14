// Copyright 2011 Google Inc. All Rights Reserved.

package org.keyczar;

import org.keyczar.enums.KeyPurpose;
import org.keyczar.enums.KeyStatus;
import org.keyczar.enums.KeyType;
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
  private KeyMetadata meta = null;
  private KeyczarPublicKey key;

  public X509CertificateReader(KeyPurpose purpose, InputStream certificateStream)
      throws KeyczarException {
    if (purpose == null) {
      throw new KeyczarException("X509Certificate purpose must not be null");
	}
	if (certificateStream == null) {
	  throw new KeyczarException("X509Certificate stream must not be null");
	}
    this.purpose = purpose;
    this.certificateStream = certificateStream;
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
      readX509Certificate(certificateStream);
    }
  }

  /**
   * Converts a PEM or DER-formatted X.509 certificate file into the appropriate
   * KeyczarKey object.
   * @throws KeyczarException
   */
  private void readX509Certificate(InputStream certificateStream) throws KeyczarException {
    try {
      parseCertificate(certificateStream);
      constructMetadata();
    } catch (CertificateException e) {
      throw new KeyczarException(Messages.getString("KeyczarTool.InvalidCertificate"));
    }
  }

  private void constructMetadata() throws KeyczarException {
    if (purpose == KeyPurpose.ENCRYPT && key.getType() == KeyType.DSA_PUB) {
      throw new KeyczarException(Messages.getString("Keyczartool.InvalidUseOfDsaKey"));
    }
    meta = new KeyMetadata("imported from certificate", purpose, key.getType());
    meta.addVersion(new KeyVersion(1, KeyStatus.PRIMARY, true /* exportable */));
  }

  private void parseCertificate(InputStream certificateStream) throws CertificateException,
      KeyczarException {
    Certificate certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(certificateStream);
    PublicKey publicKey = certificate.getPublicKey();

    if (publicKey instanceof RSAPublicKey) {
      key = readRsaX509Certificate(publicKey);
    } else if (publicKey instanceof DSAPublicKey) {
      key = readDsaX509Certificate(publicKey);
    } else {
      throw new KeyczarException("Unrecognized key type " + publicKey.getAlgorithm() +
          " in certificate");
    }
  }

  private static DsaPublicKey readDsaX509Certificate(PublicKey publicKey) throws KeyczarException {
    DSAPublicKey jcePublicKey = (DSAPublicKey) publicKey;
    DsaPublicKey key = new DsaPublicKey();
    key.set(jcePublicKey.getY(), jcePublicKey.getParams().getP(), jcePublicKey.getParams().getQ(),
        jcePublicKey.getParams().getG());
    return key;
  }

  private static RsaPublicKey readRsaX509Certificate(PublicKey publicKey) throws KeyczarException {
    RSAPublicKey jceKey = (RSAPublicKey) publicKey;
    RsaPublicKey key = new RsaPublicKey();
    key.set(jceKey.getModulus().bitLength(), jceKey.getModulus(), jceKey.getPublicExponent());
    return key;
  }
}
