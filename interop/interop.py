#!/usr/bin/python
#
# Copyright 2013 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Testcases for interop of python keyczar.

Operations are basic functions of keyczar like encrypting, signing,
attached signing, or unversioned signing. Each operation generates
data via its generate function, saves it to a file, and verifies
data using its test function. These operations are implemented in
each implementation and then called via a command line interface
which takes a JSON string as a parameter.

To add a new key type or size, simply modify interopAlgorithms.json

To add tests that will be ignored, modify ignoredTests.

To add a new operation, modify operations.json and implement the operation
in each implementation listed in the implementation file.

To add a new implementation, create an interop test file that processes the
json and produces the result of the create, test, and generate commands.
Then add the implementation and the path to the test file to
implementations.json.

@author: dlundberg@google.com (Devin Lundberg)
"""
import itertools
import json
import os
import subprocess
import unittest

from keyczar import util


ALGORITHM_JSON = "config/interopAlgorithms.json"
INTEROP_DATA = "keys"
IGNORED_TESTS = "config/ignoredTests.json"
OPERATIONS = "config/operations.json"
IMPLEMENTATIONS = "config/implementations.json"
TESTDATA = "This is some test data."


class InteropTestRunner(object):

  def __init__(self):
    """ loads the json data from the config files """
    self.algorithms = json.loads(util.ReadFile(ALGORITHM_JSON))
    self.ignored_tests = json.loads(util.ReadFile(IGNORED_TESTS))
    self.operations = json.loads(util.ReadFile(OPERATIONS))
    self.implementations = json.loads(util.ReadFile(IMPLEMENTATIONS))
    self._InitializeIgnoredTests()

  def _InitializeIgnoredTests(self):
    """ Allows for wildcards ("*") in the ignored tests json file """
    if "*" in self.ignored_tests:
      for implementation in self.implementations:
        for operation, algorithms in self.ignored_tests["*"].iteritems():
          for algorithm, options in algorithms.iteritems():
            self._AddIgnoredTest(implementation, operation, algorithm, options)
      del self.ignored_tests["*"]
    for implementation in self.ignored_tests:
      if "*" in self.ignored_tests[implementation]:
        for operation in self.operations:
          for algorithm, options in (
              self.ignored_tests[implementation]["*"].iteritems()):
            self._AddIgnoredTest(implementation, operation, algorithm, options)
        del self.ignored_tests[implementation]["*"]
    for implementation in self.ignored_tests:
      for operation in self.ignored_tests[implementation]:
        if "*" in self.ignored_tests[implementation][operation]:
          for algorithm in self.GetKeysByPurpose():
            options = self.ignored_tests[implementation][operation]["*"]
            self._AddIgnoredTest(implementation, operation, algorithm, options)
          del self.ignored_tests[implementation][operation]["*"]
    for implementation in self.ignored_tests:
      for operation in self.ignored_tests[implementation]:
        for algorithm, options in self.ignored_tests[implementation][operation].iteritems():
          if options == "*":
            self._AddIgnoredTest(implementation, operation, algorithm, options)

  def _AddIgnoredTest(self, implementation, operation, algorithm, options):
    """ adds an ignored test for the specific parameters """
    if implementation not in self.ignored_tests:
      self.ignored_tests[implementation] = {}
    if operation not in self.ignored_tests[implementation]:
      self.ignored_tests[implementation][operation] = {}
    if algorithm not in self.ignored_tests[implementation][operation]:
      self.ignored_tests[implementation][operation][algorithm] = []
    if options == "*":
      all_options = self.operations[operation]["generateOptions"]
      options = itertools.product(*all_options)
      self.ignored_tests[implementation][operation][algorithm] = []
    for option in options:
      self.ignored_tests[implementation][operation][algorithm].append(option)

  def GetKeysByPurpose(self, purpose=""):
    """ Gets names for all algorithms or ones with the given purpose. """
    if purpose:
      algorithms = [algorithm for algorithm in self.algorithms
                    if self.algorithms[algorithm]["purpose"] == purpose]
    else:
      algorithms = self.algorithms.keys()
    algorithms_with_sizes = []
    for algorithm in algorithms:
      for size in self.algorithms[algorithm]["keySizes"]:
        algorithms_with_sizes.append(algorithm + str(size))
    return algorithms_with_sizes

  def _IsException(self, implementation, operation, algorithm, options):
    """ Returns true if the configuration given is supposed to be ignored. """
    if (implementation in self.ignored_tests and
        operation in self.ignored_tests[implementation] and
        algorithm in self.ignored_tests[implementation][operation]):
      exceptions = [tuple(test) for test in
                    self.ignored_tests
                    [implementation][operation][algorithm]]
      if tuple(options) in set(exceptions):
        print "Ignoring %s with %s for %s with options %s" % (
            operation, algorithm, implementation, ", ".join(options))
        return True
    return False

  def TestAll(self, operation, algorithm, generate_options):
    """ Generates all possible configurations for the Test function. """
    for implementation in self.implementations:
      all_options = self.operations[operation]["testOptions"]
      for options in itertools.product(*all_options):
        if not self._IsException(
            implementation, operation, algorithm, generate_options):
          yield (implementation, options)

  def GenerateAll(self):
    """ Generates all possible configurations for the Generate function. """
    for implementation in self.implementations:
      for operation in self.operations:
        purpose = self.operations[operation]["keytype"]
        for algorithm in self.GetKeysByPurpose(purpose):
          all_options = self.operations[operation]["generateOptions"]
          for options in itertools.product(*all_options):
            if not self._IsException(
                implementation, operation, algorithm, options):
              yield (implementation, operation, algorithm, options)

  def _MakeDirs(self, location):
    """ Makes directories, will empty the leaf if it exists """
    try:
      os.makedirs(location)
    except os.error:
      try:
        for filename in os.listdir(location):
          file_path = os.path.join(location, filename)
          if os.path.isfile(file_path):
            os.remove(file_path)
        print "overwrote %s"%location
      except os.error, e:
        print "Error accessing location: %s, error: %s"%(location, e)
        os._exit(1)

  def _GetKeyPath(self, implementation):
    """ Gets path where keysets are saved """
    return os.path.join(INTEROP_DATA, implementation)

  def _GetKeyDir(self, implementation, algorithm, size):
    """ Gets path for specific algorithm and size """
    implemenation_data = self._GetKeyPath(implementation)
    return os.path.join(implemenation_data, algorithm + str(size))

  def _CallImplementation(self, implementation, *params):
    """ Makes a call to an implementation and returns response """
    args = self.implementations[implementation] + list(params)
    try:
      return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
      raise AssertionError(e.output)

  def _Create(self, implementation, algorithm, size):
    """ Sets up necessary flags and creates keys """
    location = self._GetKeyDir(implementation, algorithm, size)
    self._MakeDirs(location)
    create_flags = self._GetCreateFlags(algorithm, size, location)
    add_key_flags = self._GetAddKeyFlags(algorithm, size, location)
    params = {
        "command": "create",
        "createFlags": create_flags,
        "addKeyFlags": add_key_flags,
        }
    print self._CallImplementation(implementation, json.dumps(params))

  def _GetCreateFlags(self, algorithm, size, location):
    """ Returns list of flags for keyczart key creation """
    name = algorithm + str(size)
    create_flags = [
        "create",
        "--name=" + name,
        "--location=" + location
        ]
    return create_flags + self.algorithms[algorithm]["createFlags"]

  def _GetAddKeyFlags(self, algorithm, size, location):
    """ Returns list of flags for add key call to keyczart """
    add_key_flags = [
        "addkey",
        "--status=primary",
        "--size=" + str(size),
        "--status=primary",
        "--location=" + location
        ]
    return add_key_flags + self.algorithms[algorithm]["addKeyFlags"]

  def CreateKeys(self):
    """ creates keys for all implementations, sizes, and algorithms """
    for implementation in self.implementations:
      for algorithm in self.algorithms:
        for size in self.algorithms[algorithm]["keySizes"]:
          self._Create(implementation, algorithm, size)

  def _Generate(self, implementation, operation, algorithm, options):
    """ Sets up arguments and calls generate function for given parameters. """
    args = {
        "command": "generate",
        "operation": operation,
        "keyPath": self._GetKeyPath(implementation),
        "algorithm": algorithm,
        "generateOptions": options,
        "testData": TESTDATA
        }
    return self._CallImplementation(implementation, json.dumps(args))

  def _Test(self, output, test_implementation, generate_implementation,
            operation, algorithm, generate_options, test_options):
    """ Sets up arguments and calls test function for given parameters. """
    args = {
        "command": "test",
        "operation": operation,
        "keyPath": self._GetKeyPath(generate_implementation),
        "algorithm": algorithm,
        "generateOptions": generate_options,
        "testOptions": test_options,
        "output": output,
        "testData": TESTDATA
        }
    return self._CallImplementation(test_implementation, json.dumps(args))

  def InteropTestGenerator(self, *args):
    def Test(_):
      self._Test(*args)
    return Test

  def SetupInteropTests(self):
    """
    Dynamically creates test cases.

    For each operation, algorithm, keysize, and

    Should be called before loaded into unittest
    """
    for params in self.GenerateAll():
      generate_implementation, operation, algorithm, generate_options = params
      output = self._Generate(
          generate_implementation, operation, algorithm, generate_options)
      for test_implementation, test_options in self.TestAll(
          operation, algorithm, generate_options):
        test_name = "test_%s_generated_by_%s_%s_%s_%s_%s" % (
            test_implementation,
            generate_implementation,
            operation,
            algorithm,
            "_".join(generate_options),
            "_".join(test_options),
            )

        test = self.InteropTestGenerator(
            output,
            test_implementation,
            generate_implementation,
            operation,
            algorithm,
            generate_options,
            test_options)
        setattr(InteropTest, test_name, test)


class InteropTest(unittest.TestCase):
  """ unittests to run interop tests """
  pass


def Suite():
  alltests = unittest.TestSuite([
      unittest.TestLoader().loadTestsFromTestCase(InteropTest)
      ])
  return alltests


if __name__ == "__main__":
  runner = InteropTestRunner()
  runner.CreateKeys()
  runner.SetupInteropTests()
  unittest.main(defaultTest="Suite")
