package org.keyczar.jce;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;

/**
 * This class implements an EC key factory capable of generating:
 * <ul>
 * <li>Private keys from PKCS#8 and ECPrivateKeySpec
 * <li>Public keys from X.509 and ECPublicKeySpec
 * </ul>
 * 
 * @author martclau@gmail.com
 * 
 */
public class EcKeyFactoryImpl extends KeyFactorySpi {

  public EcKeyFactoryImpl() {
    super();
  }

  // "Translate" e.g. {1 2 840 10045 2 1} to 1.2.840.10045.2.1
  private static String decodeOID(ASN1Value val) throws Exception {
    OBJECT_IDENTIFIER.Template ot = new OBJECT_IDENTIFIER.Template();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    val.encode(baos);
    OBJECT_IDENTIFIER o = (OBJECT_IDENTIFIER) ot
        .decode(new ByteArrayInputStream(baos.toByteArray()));
    StringBuffer sb = new StringBuffer();
    long[] nums = o.getNumbers();
    for (int i = 0; i < nums.length - 1; i++) {
      sb.append(nums[i] + ".");
    }
    sb.append(nums[nums.length - 1]);
    return sb.toString();
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
      throws InvalidKeySpecException {
    if (keySpec instanceof PKCS8EncodedKeySpec) {
      try {
        PrivateKeyInfo.Template pkiTemp = new PrivateKeyInfo.Template();
        byte[] data = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
        PrivateKeyInfo pki = (PrivateKeyInfo) pkiTemp
            .decode(new ByteArrayInputStream(data));

        AlgorithmIdentifier algid = pki.getPrivateKeyAlgorithm();
        if (!algid.getOID().toString().equals("{1 2 840 10045 2 1}")) // ecPublicKey
          throw new IllegalArgumentException("Unsupported key");

        ECParameterSpec params = EcCore.getParams(decodeOID(algid
            .getParameters()));

        SEQUENCE.Template foo = new SEQUENCE.Template();
        foo.addElement(new INTEGER.Template());
        foo.addElement(new OCTET_STRING.Template());

        SEQUENCE ecPrivateKey = (SEQUENCE) foo.decode(new ByteArrayInputStream(
            pki.getEncoded()));
        OCTET_STRING arrhh = (OCTET_STRING) ecPrivateKey.elementAt(1);
        return new EcPrivateKeyImpl(new BigInteger(1, arrhh.toByteArray()),
            params);
      } catch (Exception e) {
        throw new InvalidKeySpecException("Invalid key encoding", e);
      }
    }
    if (keySpec instanceof ECPrivateKeySpec) {
      ECPrivateKeySpec spec = (ECPrivateKeySpec) keySpec;
      return new EcPrivateKeyImpl(spec.getS(), spec.getParams());
    }
    throw new IllegalArgumentException("Type of KeySpec is not supported");
  }

  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec)
      throws InvalidKeySpecException {
    if (keySpec instanceof X509EncodedKeySpec) {
      try {
        SEQUENCE.Template outer = new SEQUENCE.Template();
        outer.addElement(AlgorithmIdentifier.getTemplate());
        outer.addElement(BIT_STRING.getTemplate());

        byte[] data = ((X509EncodedKeySpec) keySpec).getEncoded();
        SEQUENCE ecPublicKey = (SEQUENCE) outer
            .decode(new ByteArrayInputStream(data));

        AlgorithmIdentifier algid = (AlgorithmIdentifier) ecPublicKey
            .elementAt(0);
        if (!algid.getOID().toString().equals("{1 2 840 10045 2 1}")) // ecPublicKey
          throw new IllegalArgumentException("Unsupported key");

        ECParameterSpec params = EcCore.getParams(decodeOID(algid
            .getParameters()));

        BIT_STRING bs = (BIT_STRING) ecPublicKey.elementAt(1);
        data = bs.getBits();

        return new EcPublicKeyImpl(EcCore.bytesToECPoint(data, params), params);
      } catch (Exception e) {
        throw new InvalidKeySpecException("Invalid key encoding", e);
      }
    }
    if (keySpec instanceof ECPublicKeySpec) {
      ECPublicKeySpec spec = (ECPublicKeySpec) keySpec;
      return new EcPublicKeyImpl(spec.getW(), spec.getParams());
    }
    throw new IllegalArgumentException("Type of KeySpec is not supported");
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) {
    throw new UnsupportedOperationException("Method not supported");
  }

  @Override
  protected Key engineTranslateKey(Key key) {
    throw new UnsupportedOperationException("Method not supported");
  }
}
