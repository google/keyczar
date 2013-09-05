package org.keyczar.interop;

import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interop.operations.Operation;

import java.util.Map;
import java.util.Set;

/**
 * Class used for gson data to call test commands
 */
public class Tester {
  @SuppressWarnings("unused")
  private final String command;
  private final String operation;
  private final String keyPath;
  private final String algorithm;
  private final Map<String, String> generateOptions;
  private final Map<String, String> testOptions;
  private final Map<String, String> output;
  private final String testData;
  
  public Tester(
      String command, String operation, String keyPath, String algorithm, 
      Map<String, String> generateOptions, Map<String, String> testOptions,
      Map<String, String> output, String testData) {
    this.command = command;
    this.operation = operation;
    this.keyPath = keyPath;
    this.algorithm = algorithm;
    this.generateOptions = generateOptions;
    this.testOptions = testOptions;
    this.output = output;
    this.testData = testData;
  }
  
  public void test() throws KeyczarException {
    Operation op = Operation.getOperationByName(operation, keyPath, testData);
    op.test(output, algorithm, generateOptions, testOptions);
  }
}