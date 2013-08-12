package org.keyczar.interop.operations;

import org.keyczar.Signer;
import org.keyczar.Verifier;
import org.keyczar.exceptions.KeyczarException;

import java.util.Set;

/**
 * Tests functionality of attached signing
 */
public class AttachedSignOperation extends Operation {

  public AttachedSignOperation(String keyPath, String testData) {
    super(keyPath, testData);
  }

  @Override
  public byte[] generate(String algorithm, Set<String> generateParams) throws KeyczarException{
    Signer signer = new Signer(getKeyPath(algorithm));
    if (generateParams.contains("encoded")) {
      // String signature = signer.attachedSign(testData, "".getBytes());
      // Not implemented
      return "".getBytes();
    } else if (generateParams.contains("unencoded")) {
      byte[] signature = signer.attachedSign(testData.getBytes(), "".getBytes());
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
      Signer verifier = new Signer(getKeyPath(algorithm));
      if (generateParams.contains("encoded")) {
        throw new KeyczarException("Not Implemented");
      } else if (generateParams.contains("unencoded")) {
        assert(verifier.verify(testData.getBytes(), output));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else if (testParams.contains("verifier")) {
      Verifier verifier = new Verifier(getKeyPath(algorithm));
      if (generateParams.contains("encoded")) {
        throw new KeyczarException("Not Implemented");
      } else if (generateParams.contains("unencoded")) {
        assert(verifier.attachedVerify(testData.getBytes(), output));
      } else {
        throw new KeyczarException("Expects encoded or unencoded in parameters");
      }
    } else {
      throw new KeyczarException("Expects signer or verifier in parameters");
    }  
  }

}
