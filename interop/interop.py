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
import sys
import unittest


ALGORITHM_JSON = "config/interopAlgorithms.json"
CRYPTED_KEY_SET_ALGORITHM = "aes128"
INTEROP_DATA = "keys"
IGNORED_TESTS = "config/ignoredTests.json"
KEY_SET_OPTIONS = "config/keySetOptions.json"
OPERATIONS = "config/operations.json"
IMPLEMENTATIONS = "config/implementations.json"
TESTDATA = "This is some test data."


def ReadFile(loc):
  """
  Read data from file at given location.

  @param loc: name of file to read from
  @type loc: string

  @return: contents of the file
  @rtype: string

  @raise KeyczarError: if unable to read from file because of IOError
  """
  try:
    return open(loc).read()
  except IOError:
    raise Exception("Unable to read file %s." % loc)


class InteropLogger(object):
  """ Logs output for interop testing. """

  def __init__(self, verbose=False):
    self.collection = {}
    self.verbose = verbose

  def Output(self, string):
    print string

  def Debug(self, string):
    if self.verbose:
      print string

  def Collect(self, message, details):
    if message not in self.collection:
      self.collection[message] = []
    self.collection[message].append(details)

  def OutputCollection(self):
    for message in self.collection:
      print "%d Events: %s" % (len(self.collection[message]), message)
      if self.verbose:
        for details in self.collection[message]:
          print "    %s" % details
    self.collection = {}


class Keyset(object):
  """ Represents a key set"""

  @classmethod
  def GetGenerateKeysets(cls, purpose, interop_test_runner):
    """
    Generates all keysets for the specified purpose

    @param purpose: specifed purpose
    @type purpose: string, either "crypt" or "sign"

    @param interop_test_runner: the class holding the configuration
    @type interop_test_runner: an instance of InteropTestRunner
    """
    algorithms = interop_test_runner.algorithms
    key_set_options = interop_test_runner.key_set_options

    for algorithm in algorithms:
      if algorithms[algorithm]["purpose"] == purpose:
        for size in algorithms[algorithm]["keySizes"]:
          if purpose == "crypt" and algorithms[algorithm]["asymmetric"]:
            yield cls(key_set_options, algorithm, size, "encrypt")
          yield cls(key_set_options, algorithm, size, purpose)

  @classmethod
  def GetTestKeysets(cls, generate_keyset, interop_test_runner):
    """
    Generates all test keysets to be used with this generate keyset

    This allows for a distinction to be made between public and private keys and
    for different options to be passed to the different types of keys.

    @param generate_keyset: The keyset used for the Generate function
    @type generate_keyset: Keyset

    @param interop_test_runner: the class holding the configuration
    @type interop_test_runner: an instance of InteropTestRunner

    @raises ValueError: if the generate purpose doesn't fit a known purpose
    """
    algorithms = interop_test_runner.algorithms
    if generate_keyset.purpose == "crypt":
      return [generate_keyset]
    elif generate_keyset.purpose == "encrypt":
      return [cls._SwitchPurpose(generate_keyset, "crypt")]
    elif generate_keyset.purpose == "sign":
      if algorithms[generate_keyset.algorithm]["asymmetric"]:
        return [generate_keyset, cls._SwitchPurpose(generate_keyset, "verify")]
      return [generate_keyset]
    else:
      raise ValueError("Unexpected generate purpose:" + generate_keyset.purpose)

  @classmethod
  def _SwitchPurpose(cls, keyset, purpose):
    """ generates a new keyset with a different purpose """
    return cls(keyset.key_set_options, keyset.algorithm, keyset.size, purpose)

  def __init__(self, key_set_options, algorithm, size, purpose):
    self.key_set_options = key_set_options
    self.algorithm = algorithm
    self.size = size
    self.purpose = purpose

  def __repr__(self):
    return "Keyset(%s,%d,%s)"%(self.algorithm, self.size, self.purpose)

  @property
  def name(self):
    return self.algorithm + str(self.size)

  def Options(self, option_string):
    return self.key_set_options[self.purpose][option_string]

  @property
  def test_options(self):
    return self.Options("testOptions")

  @property
  def generate_options(self):
    return self.Options("generateOptions")


class InteropTestRunner(object):
  """ Class for running interop testing"""

  def __init__(self, logger):
    """ loads the json data from the config files """
    self.logger = logger
    self.algorithms = json.loads(ReadFile(ALGORITHM_JSON))
    self.ignored_tests = json.loads(ReadFile(IGNORED_TESTS))
    self.operations = json.loads(ReadFile(OPERATIONS))
    self.implementations = json.loads(ReadFile(IMPLEMENTATIONS))
    self.key_set_options = json.loads(ReadFile(KEY_SET_OPTIONS))
    self.macros = {"ALL_SIGNING_KEYS":
                   [ks.name for ks in Keyset.GetGenerateKeysets("sign", self)]}

  def _IsException(self, implementation, operation, algorithm, options):
    """ Returns true if the configuration given is supposed to be ignored. """
    for ignored_test in self.ignored_tests:
      contains = lambda v, name: any(x in ignored_test[name] for x in (v, "*"))
      if (contains(implementation, "implementation") and
          contains(algorithm, "algorithm") and
          contains(operation, "operation")):
        ignored_ops = ignored_test["options"]
        ignored = True
        for option_name in ignored_ops:
          if option_name != "*" and (
              option_name not in options or
              options[option_name] not in ignored_ops[option_name]):
            ignored = False

        if ignored:
          self.logger.Collect(
              "Ignoring tests because %s" % ignored_test["reason"],
              "%s with %s for %s with options %s" % (
                  operation, algorithm,
                  implementation, ", ".join(options.values())))
          return True
    return False

  def _Options(self, operation, keyset, option_string):
    """
    Iterates over all options possible for that operation/keyset/option_string.

    @param operation: The name of the operation to get options from
    @type operation: string

    @param keyset: type of algorithm/keyset to use
    @type keyset: Keyset

    @param option_string: specifies what type of options
    @type option_string: string, either "generateOptions" or "testOptions"
    """
    operation_options = self.operations[operation][option_string]
    key_set_options = keyset.Options(option_string)
    option_dict = dict(key_set_options.items() + operation_options.items())
    if not option_dict:
      yield {}
    else:
      for name, option_list in option_dict.iteritems():
        if isinstance(option_list, unicode):
          option_dict[name] = self.macros[option_list]
      names, all_options = zip(*option_dict.items())
      for options in itertools.product(*all_options):
        yield dict([(name, option) for name, option in zip(names, options)])

  def _TestAll(self, operation, keyset, generate_options):
    """ Generates all possible configurations for the Test function. """
    for implementation in self.implementations:
      for test_keyset in Keyset.GetTestKeysets(keyset, self):
        for options in self._Options(operation, test_keyset, "testOptions"):
          combined_options = dict(options.items() + generate_options.items())
          if not self._IsException(
              implementation, operation, keyset.name, combined_options):
            yield (implementation, options)

  def _GenerateAll(self):
    """ Generates all possible configurations for the Generate function. """
    for implementation in self.implementations:
      for operation in self.operations:
        purpose = self.operations[operation]["keytype"]
        for keyset in Keyset.GetGenerateKeysets(purpose, self):
          for options in self._Options(operation, keyset, "generateOptions"):
            if not self._IsException(
                implementation, operation, keyset.name, options):
              yield (implementation, operation, keyset, options)

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
        self.logger.Debug("overwrote %s" % location)
      except os.error, e:
        self.logger.Output(
            "Error accessing location: %s, error: %s" % (location, e))
        os._exit(1)

  def _GetKeyPath(self, implementation):
    """ Gets path where keysets are saved """
    return os.path.join(INTEROP_DATA, implementation)

  def _GetKeyDir(self, implementation, name):
    """ Gets path for specific algorithm and size """
    implemenation_data = self._GetKeyPath(implementation)
    return os.path.join(implemenation_data, name)

  def _CallImplementation(self, implementation, *params):
    """ Makes a call to an implementation and returns response """
    args = self.implementations[implementation] + list(params)
    try:
      return subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
      cmd = subprocess.list2cmdline(args)
      raise Exception("%s failed:\n %s" % (cmd, e.output))

  def _Create(self, implementation, algorithm, size, asymmetric):
    """ Sets up necessary flags and creates keys """
    location = self._GetKeyDir(implementation, algorithm + str(size))
    self._MakeDirs(location)
    create_flags = self._GetCreateFlags(algorithm, size, location)
    add_key_flags = self._GetAddKeyFlags(algorithm, size, location)
    commands = [create_flags]
    commands += 2 * [add_key_flags]
    if asymmetric:
      self._MakeDirs(location + "public")
      commands.append(self._GetPubKeyFlags(location))
    params = {
        "command": "create",
        "keyczartCommands": commands
    }
    self.logger.Debug(
        self._CallImplementation(implementation, json.dumps(params)))

  def _CreateEncrypted(
      self, implementation, algorithm, size, crypter, _):
    """ Sets up necessary flags and creates keys """
    location = self._GetKeyDir(implementation, algorithm + str(size) + crypter)
    crypter_location = self._GetKeyDir(implementation, crypter)
    self._MakeDirs(location)
    create_flags = self._GetCreateFlags(algorithm, size, location)
    add_key_flags = self._GetAddKeyFlags(
        algorithm, size, location, "--crypter=" + crypter_location)
    commands = [create_flags]
    commands.append(add_key_flags)
    params = {
        "command": "create",
        "keyczartCommands": commands
    }
    self.logger.Debug(
        self._CallImplementation(implementation, json.dumps(params)))

  def _GetCreateFlags(self, algorithm, size, location):
    """ Returns list of flags for keyczart key creation """
    name = algorithm + str(size)
    create_flags = [
        "create",
        "--name=" + name,
        "--location=" + location
        ]
    return create_flags + self.algorithms[algorithm]["createFlags"]

  def _GetAddKeyFlags(self, algorithm, size, location, *flags):
    """ Returns list of flags for add key call to keyczart """
    add_key_flags = [
        "addkey",
        "--status=primary",
        "--size=" + str(size),
        "--location=" + location
        ]
    add_key_flags += flags
    add_key_flags += self.algorithms[algorithm]["addKeyFlags"]
    return add_key_flags

  def _GetPubKeyFlags(self, location, *flags):
    """ Returns list of flags for pub key call to keyczart """
    pub_key_flags = [
        "pubkey",
        "--destination=" + location + "public",
        "--location=" + location,
        ]
    pub_key_flags += flags
    return pub_key_flags

  def CreateKeys(self):
    """ creates keys for all implementations, sizes, and algorithms """
    for implementation in self.implementations:
      for algorithm in self.algorithms:
        for size in self.algorithms[algorithm]["keySizes"]:
          self._Create(implementation, algorithm, size,
                       self.algorithms[algorithm]["asymmetric"])
    for implementation in self.implementations:
      for algorithm in self.algorithms:
        for size in self.algorithms[algorithm]["keySizes"]:
          self._CreateEncrypted(
              implementation, algorithm, size, CRYPTED_KEY_SET_ALGORITHM,
              self.algorithms[algorithm]["asymmetric"])

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

  def _Test(self, output_json, test_implementation, generate_implementation,
            operation, algorithm, generate_options, test_options):
    """ Sets up arguments and calls test function for given parameters. """
    output = json.loads(output_json)
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
    for params in self._GenerateAll():
      generate_implementation, operation, keyset, generate_options = params
      output = self._Generate(
          generate_implementation, operation, keyset.name, generate_options)
      for test_implementation, test_options in self._TestAll(
          operation, keyset, generate_options):
        test_name = "test_%s_generated_by_%s_%s_%s_%s_%s" % (
            test_implementation,
            generate_implementation,
            operation,
            keyset.name,
            "_".join(generate_options.values()),
            "_".join(test_options.values()),
            )

        test = self.InteropTestGenerator(
            output,
            test_implementation,
            generate_implementation,
            operation,
            keyset.name,
            generate_options,
            test_options)
        setattr(self.InteropTest, test_name, test)
    self.logger.OutputCollection()

  def DisplayTests(self):
    """ iterates through all options and prints out tests that would be ran"""
    tests = []
    for params in self._GenerateAll():
      generate_implementation, operation, keyset, generate_options = params
      for test_implementation, test_options in self._TestAll(
          operation, keyset, generate_options):
        tests.append("test_%s_generated_by_%s_%s_%s_%s_%s" % (
            test_implementation,
            generate_implementation,
            operation,
            keyset.name,
            "_".join(["%s=%s"%o for o in generate_options.items()]),
            "_".join(["%s=%s"%o for o in test_options.items()]),
            ))
    for test in sorted(tests):
      self.logger.Output(test)

  def DisplayOptions(self):
    """
    Iterates through operations and keyset types and prints possible options.
    """
    test_dict = {}
    generate_dict = {}
    # First it reconstructs the dictionary of lists of options
    for operation in self.operations:
      purpose = self.operations[operation]["keytype"]
      for keyset in Keyset.GetGenerateKeysets(purpose, self):
        options_list = [options for options in
                        self._Options(operation, keyset, "generateOptions")]
        if operation not in generate_dict:
          generate_dict[operation] = dict()
        for options in options_list:
          for option in options:
            if option not in generate_dict[operation]:
              generate_dict[operation][option] = set()
            generate_dict[operation][option].add(options[option])
        for test_keyset in Keyset.GetTestKeysets(keyset, self):
          options_list = [option for option in
                          self._Options(operation, test_keyset, "testOptions")]
          if operation not in test_dict:
            test_dict[operation] = dict()
          for options in options_list:
            for option in options:
              if option not in test_dict[operation]:
                test_dict[operation][option] = set()
              test_dict[operation][option].add(options[option])

    # Then it prints out this output.
    self.logger.Output("Generate Options:")
    for operation in generate_dict:
      self.logger.Output("  %s:" % operation)
      for option_name, options in generate_dict[operation].iteritems():
        self.logger.Output("    %s: %s" % (option_name, str(list(options))))

    self.logger.Output("\nTest Options:")
    for operation in test_dict:
      self.logger.Output("  %s:" % (operation))
      for option_name, options in test_dict[operation].iteritems():
        self.logger.Output("    %s: %s" % (option_name, str(list(options))))

  class InteropTest(unittest.TestCase):
    """ unittests to run interop tests """
    pass

  def RunTests(self):
    suite = unittest.TestLoader().loadTestsFromTestCase(self.InteropTest)
    unittest.TextTestRunner().run(suite)


def Usage():
  print ("Interoperability testing for Keyczar\n"
         "         ./interop.py [--create=(y|n)] [--verbose=(y|n)]\n"
         "         ./interop.py display\n"
         "         ./interop.py options\n"
         "Run from the interop directory. Optional flags include:\n"
         "      --create         (y/n) whether to create keys (default:y)\n"
         "      --verbose        (y/n) verbose logging (default:n)\n"
         "display will print all tests to be ran.\n"
         "options shows you the possible options for each of the operations\n")
  return 1


def main(argv):
  flags = {"create": "y", "verbose": "n"}
  for arg in argv:
    if arg == "display":
      logger = InteropLogger(verbose=False)
      runner = InteropTestRunner(logger)
      runner.DisplayTests()
      return
    elif arg == "options":
      logger = InteropLogger(verbose=False)
      runner = InteropTestRunner(logger)
      runner.DisplayOptions()
      return
    elif arg.startswith("--"):
      arg = arg[2:]  # trim leading dashes
      if arg in ("help", "h"):
        return Usage()
      try:
        [flag, val] = arg.split("=")
        if flag not in flags:
          raise ValueError("flag not in flags")
        flags[flag] = val
      except ValueError:
        print "Flags incorrectly formatted"
        return Usage()
    else:
      return Usage()
  if flags["create"] not in ("y", "n") or flags["verbose"] not in ("y", "n"):
    return Usage()
  if flags["verbose"] == "y":
    logger = InteropLogger(verbose=True)
  else:
    logger = InteropLogger(verbose=False)
  runner = InteropTestRunner(logger)
  if flags["create"] == "y":
    logger.Output("Creating Keys")
    runner.CreateKeys()
  logger.Output("Generating Data")
  runner.SetupInteropTests()
  logger.Output("Running Tests")
  runner.RunTests()

if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))

