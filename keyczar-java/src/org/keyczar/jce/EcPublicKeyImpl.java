package org.keyczar.jce;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.SEQUENCE;

/**
 * This class implements EC public keys.
 * 
 * @author martclau@gmail.com
 * 
 */
public class EcPublicKeyImpl implements ECPublicKey {

  private static final long serialVersionUID = -2181476758766123036L;

  private BigInteger x;
  private BigInteger y;
  ECParameterSpec params;

  EcPublicKeyImpl(BigInteger x, BigInteger y, ECParameterSpec params) {
    this.x = x;
    this.y = y;
    this.params = params;
  }

  EcPublicKeyImpl(ECPoint W, ECParameterSpec params) {
    this.x = W.getAffineX();
    this.y = W.getAffineY();
    this.params = params;
  }


  public ECPoint getW() {
    return new ECPoint(x, y);
  }

  public String getAlgorithm() {
    return "EC";
  }

  public byte[] getEncoded() {
    SEQUENCE outer = new SEQUENCE();

    SEQUENCE algid = new SEQUENCE();
    algid.addElement(new OBJECT_IDENTIFIER("1.2.840.10045.2.1"));
    algid.addElement(new OBJECT_IDENTIFIER(EcCore.getOID(params)));
    outer.addElement(algid);

    BIT_STRING ecPublivKey = new BIT_STRING(EcCore.ecPointToBytes(getW(),
        params), 0);
    outer.addElement(ecPublivKey);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      outer.encode(baos);
    } catch (IOException ioe) {
      throw new RuntimeException("Internal ASN.1 encoding error", ioe);
    }
    return baos.toByteArray();
  }

  public String getFormat() {
    return "X.509";
  }

  public ECParameterSpec getParams() {
    return params;
  }

  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();
    int bitlen = params.getOrder().bitLength();
    sb.append("GooKey EC public key, " + bitlen + " bit\n");
    sb.append("  Public value (x coordinate): " + x.toString(16) + "\n");
    sb.append("  Public value (y coordinate): " + y.toString(16) + "\n");
    sb.append("  Parameters: " + EcCore.getFriendlyName(params) + " ("
        + EcCore.getOID(params) + ")");
    return sb.toString();
  }
}
