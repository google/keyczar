package org.keyczar.jce;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;

/**
 * This class implements EC private keys.
 * 
 * @author martclau@gmail.com
 * 
 */
public class EcPrivateKeyImpl implements ECPrivateKey {

  private static final long serialVersionUID = -237229630170977756L;

  private BigInteger S;
  private ECParameterSpec params;

  EcPrivateKeyImpl(BigInteger S, ECParameterSpec params) {
    this.S = S;
    this.params = params;
  }

  public BigInteger getS() {
    return S;
  }

  public String getAlgorithm() {
    return "EC";
  }

  public byte[] getEncoded() {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    SEQUENCE privateKeyInfo = new SEQUENCE();
    privateKeyInfo.addElement(new INTEGER(0));

    SEQUENCE algid = new SEQUENCE();
    algid.addElement(new OBJECT_IDENTIFIER("1.2.840.10045.2.1"));
    algid.addElement(new OBJECT_IDENTIFIER(EcCore.getOID(params)));
    privateKeyInfo.addElement(algid);

    SEQUENCE ecPrivateKey = new SEQUENCE();
    ecPrivateKey.addElement(new INTEGER(1));
    ecPrivateKey
        .addElement(new OCTET_STRING(EcCore.fieldElemToBytes(S, params)));

    try {
      ecPrivateKey.encode(baos);
    } catch (IOException ioe) {
      throw new RuntimeException("Internal ASN.1 encoding error", ioe);
    }

    privateKeyInfo.addElement(new OCTET_STRING(baos.toByteArray()));

    baos.reset();
    try {
      privateKeyInfo.encode(baos);
    } catch (IOException ioe) {
      throw new RuntimeException("Internal ASN.1 encoding error", ioe);
    }

    return baos.toByteArray();
  }

  public String getFormat() {
    return "PKCS#8";
  }

  public ECParameterSpec getParams() {
    return params;
  }

  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();
    int bitlen = params.getOrder().bitLength();
    sb.append("GooKey EC private key, " + bitlen + " bit\n");
    sb.append("  Private value: " + S.toString(16) + "\n");
    sb.append("  Parameters: " + EcCore.getFriendlyName(params) + " ("
        + EcCore.getOID(params) + ")");
    return sb.toString();
  }
}
