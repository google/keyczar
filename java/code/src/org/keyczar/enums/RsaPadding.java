package org.keyczar.enums;

import java.security.interfaces.RSAPublicKey;

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.util.Util;

public enum RsaPadding {
  OAEP("RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING"),
  PKCS("RSA/ECB/PKCS1PADDING");

  private final String cryptAlgorithm;

  private RsaPadding(String cryptAlgorithm) {
    this.cryptAlgorithm = cryptAlgorithm;
  }

  public String getCryptAlgorithm() {
    return cryptAlgorithm;
  }

  public byte[] computeFullHash(RSAPublicKey key) throws KeyczarException {
    switch (this) {
      case OAEP:
        return Util.prefixHash(
            Util.stripLeadingZeros(key.getModulus().toByteArray()),
            Util.stripLeadingZeros(key.getPublicExponent().toByteArray()));
      case PKCS:
        return Util.prefixHash(
            key.getModulus().toByteArray(),
            key.getPublicExponent().toByteArray());
      default:
        throw new KeyczarException("Bug! Unknown padding type");
    }
  }
}