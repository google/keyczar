package org.keyczar.interop.operations;

import org.keyczar.UnversionedSigner;
import org.keyczar.UnversionedVerifier;
import org.keyczar.exceptions.KeyczarException;

import java.util.Set;

/**
 * Tests functionality of unversioned signing
 */
public class UnversionedSignOperation extends Operation {

  public UnversionedSignOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }
  
  @Override
  public byte[] generate(String algorithm, Set<String> generateParams) throws KeyczarException{
    UnversionedSigner signer = new UnversionedSigner(getKeyPath(algorithm));
    if (generateParams.contains("encoded")) {
      String signature = signer.sign(testData);
      return signature.getBytes();
    } else if (generateParams.contains("unencoded")) {
      byte[] signature = signer.sign(testData.getBytes());
      return signature;
    } else {
      throw new KeyczarException("Expects encoded or unencoded in parameters");
    }
  }

  @Override
  public void test(
      byte[] output, String algorithm, Set<String> generateParams, Set<String> testParams)
      throws KeyczarException {
    if (testParams.contains("signer")) {
      UnversionedSigner verifier = new UnversionedSigner(getKeyPath(algorithm));
      if (generateParams.contains("encoded")) {
        assert(verifier.verify(testData, new String(output)));
      } else if (generateParams.contains("unencoded")) {
        assert(verifier.verify(testData.getBytes(), output));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else if (testParams.contains("verifier")) {
      UnversionedVerifier verifier = new UnversionedVerifier(getKeyPath(algorithm));
      if (generateParams.contains("encoded")) {
        assert(verifier.verify(testData, new String(output)));
      } else if (generateParams.contains("unencoded")) {
        assert(verifier.verify(testData.getBytes(), output));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else {
      throw new KeyczarException("Expects signer or verifier in parameters");
    }  
  }

}
