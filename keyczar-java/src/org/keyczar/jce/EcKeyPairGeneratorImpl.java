package org.keyczar.jce;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;

/**
 * This class implements an EC keypair generator.
 * 
 * @author martclau@gmail.com
 * 
 */
public class EcKeyPairGeneratorImpl extends KeyPairGeneratorSpi {

  private ECParameterSpec params;

  public EcKeyPairGeneratorImpl() {
    super();
  }

  // SEC 1, 3.2.1
  @Override
  public KeyPair generateKeyPair() {
    final BigInteger n = params.getOrder();
    BigInteger S = BigInteger.ZERO;

    do {
      S = new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
    } while (S.signum() == 0);

    BigInteger[] G = EcCore.internalPoint(params.getGenerator());
    BigInteger[] Q = EcCore.multiplyPoint(G, S, params);
    EcCore.toAffine(Q, params);

    return new KeyPair(new EcPublicKeyImpl(Q[0], Q[1], params),
        new EcPrivateKeyImpl(S, params));
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    switch (keysize) {
    case 192:
      this.params = EcCore.getParams(EcCore.EC_PARAMS_P192_OID);
      break;
    case 224:
      this.params = EcCore.getParams(EcCore.EC_PARAMS_P224_OID);
      break;
    case 256:
      this.params = EcCore.getParams(EcCore.EC_PARAMS_P256_OID);
      break;
    case 384:
      this.params = EcCore.getParams(EcCore.EC_PARAMS_P384_OID);
      break;
    case 521:
      this.params = EcCore.getParams(EcCore.EC_PARAMS_P521_OID);
      break;
    default:
      throw new IllegalArgumentException("Unsupported keysize: " + keysize);
    }
  }
}
