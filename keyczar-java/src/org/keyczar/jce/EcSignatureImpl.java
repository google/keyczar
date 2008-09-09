package org.keyczar.jce;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.SEQUENCE;

/**
 * This class implements the ECDSA signature scheme.
 * 
 * From
 * http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html:
 * "The ECDSA signature algorithms as defined in ANSI X9.62." This means that an
 * ECDSA signature is encoded as SEQUENCE { INTEGER, INTEGER } in ASN.1.
 * 
 * @author martclau@gmail.com
 * 
 */
public class EcSignatureImpl extends SignatureSpi {

  MessageDigest hash;
  ECPrivateKey privateKey;
  ECPublicKey publicKey;
  ECParameterSpec params;

  private EcSignatureImpl(String digestName) throws NoSuchAlgorithmException {
    super();
    hash = MessageDigest.getInstance(digestName);
  }

  @Override
  protected Object engineGetParameter(String param)
      throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey)
      throws InvalidKeyException {
    if (!(privateKey instanceof ECPrivateKey))
      throw new InvalidKeyException("Unsupported key type");
    this.privateKey = (ECPrivateKey) privateKey;
    this.params = this.privateKey.getParams();
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey)
      throws InvalidKeyException {
    if (!(publicKey instanceof ECPublicKey))
      throw new InvalidKeyException("Unsupported key type");
    this.publicKey = (ECPublicKey) publicKey;
    this.params = this.publicKey.getParams();
  }

  @Override
  protected void engineSetParameter(String param, Object value)
      throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  // SEC 1, 4.1.3
  @Override
  protected byte[] engineSign() throws SignatureException {
    BigInteger e = trimHash(hash.digest(), params);
    BigInteger r = BigInteger.ZERO;
    BigInteger s = BigInteger.ZERO;

    do {
      BigInteger n = params.getOrder();
      BigInteger k = BigInteger.ZERO;

      do {
        do {
          k = new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
        } while (k.signum() == 0);

        BigInteger[] G = EcCore.internalPoint(params.getGenerator());
        BigInteger[] R = EcCore.multiplyPoint(G, k, params);
        EcCore.toAffineX(R, params);

        r = R[0].mod(n);
      } while (r.signum() == 0);

      s = k.modInverse(n).multiply(e.add(privateKey.getS().multiply(r))).mod(n);

    } while (s.signum() == 0);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      // SEQUENCE seq = new SEQUENCE();
      // seq.addElement(new INTEGER(EcCore.fieldElemToBytes(r, params)));
      // seq.addElement(new INTEGER(EcCore.fieldElemToBytes(s, params)));

      // Sigh, another work around...
      SEQUENCE seq = new SEQUENCE();

      byte[] tmp = new byte[2 + (((ECFieldFp) params.getCurve().getField())
          .getFieldSize() + 7) / 8];
      tmp[0] = 0x02;
      tmp[1] = (byte) EcCore.fieldElemToBytes(r, params, tmp, 2);
      seq.addElement(new ANY(tmp));

      tmp = new byte[2 + (((ECFieldFp) params.getCurve().getField())
          .getFieldSize() + 7) / 8];
      tmp[0] = 0x02;
      tmp[1] = (byte) EcCore.fieldElemToBytes(s, params, tmp, 2);
      seq.addElement(new ANY(tmp));

      seq.encode(baos);
    } catch (Exception ex) {
      throw new SignatureException("Internal ASN.1 encoding error", ex);
    }

    return baos.toByteArray();
  }

  @Override
  protected void engineUpdate(byte b) {
    hash.update(b);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) {
    hash.update(b, off, len);

  }

  // SEC 1, 4.1.1
  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    try {
      // SEQUENCE.Template seqtemp = new SEQUENCE.Template();
      // seqtemp.addElement( INTEGER.getTemplate() );
      // seqtemp.addElement( INTEGER.getTemplate() );
      // SEQUENCE seq = (SEQUENCE)seqtemp.decode(new
      // ByteArrayInputStream(sigBytes));
      // BigInteger r = (BigInteger)seq.elementAt(0);
      // BigInteger s = (BigInteger)seq.elementAt(1);

      // Arrggg, the following is a work around: JSS creates BigIntegers
      // using BigInteger(byte[]) which, if the "sign" bit is set,
      // create negative numbers. This, of course, destroys signature
      // verification. In this case they should have used the
      // BigInteger(1,byte[])
      // constructor. Anyway, we do it manually...
      SEQUENCE.Template foo = new SEQUENCE.Template();
      foo.addElement(ANY.getTemplate());
      foo.addElement(ANY.getTemplate());
      SEQUENCE bar = (SEQUENCE) foo.decode(new ByteArrayInputStream(sigBytes));
      BigInteger r = new BigInteger(1, ((ANY) bar.elementAt(0)).getContents());
      BigInteger s = new BigInteger(1, ((ANY) bar.elementAt(1)).getContents());

      BigInteger e = trimHash(hash.digest(), params);
      BigInteger n = params.getOrder();

      // r in [1,n-1]
      if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0) return false;

      // s in [1,n-1]
      if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) return false;

      BigInteger c = s.modInverse(n);
      BigInteger u1 = e.multiply(c).mod(n);
      BigInteger u2 = r.multiply(c).mod(n);

      BigInteger[] G = EcCore.internalPoint(params.getGenerator());
      BigInteger[] W = EcCore.internalPoint(publicKey.getW());
      BigInteger[] R1 = EcCore.multiplyPoints(G, u1, W, u2, params);
      EcCore.toAffineX(R1, params);

      BigInteger v = R1[0].mod(n);

      return v.equals(r);
    } catch (Exception e) {
      throw new SignatureException("Internal error", e);
    }
  }

  private static BigInteger trimHash(final byte[] hash, ECParameterSpec params) {
    BigInteger e = new BigInteger(1, hash);
    int orderLength = params.getOrder().bitLength();
    int hashLength = 8 * hash.length;
    if (orderLength < hashLength) e = e.shiftRight(hashLength - orderLength);
    return e;
  }

  public static class SHA1 extends EcSignatureImpl {
    public SHA1() throws NoSuchAlgorithmException {
      super("SHA-1");
    }
  }

  public static class SHA256 extends EcSignatureImpl {
    public SHA256() throws NoSuchAlgorithmException {
      super("SHA-256");
    }
  }

  public static class SHA384 extends EcSignatureImpl {
    public SHA384() throws NoSuchAlgorithmException {
      super("SHA-384");
    }
  }

  public static class SHA512 extends EcSignatureImpl {
    public SHA512() throws NoSuchAlgorithmException {
      super("SHA-512");
    }
  }
}
