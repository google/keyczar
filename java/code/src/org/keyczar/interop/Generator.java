package org.keyczar.interop;

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interop.operations.Operation;

import java.util.Set;

/**
 * Class used for gson data to call generate commands
 */
public class Generator {
  @SuppressWarnings("unused")
  private final String command;
  private final String operation;
  private final String keyPath;
  private final String algorithm;
  private final Set<String> generateOptions;
  private final String testData;
  
  private Generator(
      String command, String operation, String keyPath, 
      String algorithm, Set<String> generateOptions, String testData) {
    this.command = command;
    this.operation = operation;
    this.keyPath = keyPath;
    this.algorithm = algorithm;
    this.generateOptions = generateOptions;
    this.testData = testData;
  }
  
  
  public String generate() throws KeyczarException {
    Operation op = Operation.getOperationByName(operation, keyPath, testData);
    byte[] output = op.generate(algorithm, generateOptions);
    return op.formatOutput(output);
  }
  
}
