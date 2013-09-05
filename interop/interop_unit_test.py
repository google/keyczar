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

import json
import unittest

import interop


class MockLogger(object):
  """Mock Logging class for testing"""

  def __init__(self, verbose=False):
    pass

  def Output(self, string):
    pass

  def Debug(self, string):
    pass

  def Collect(self, message, details):
    pass

  def OutputCollection(self):
    pass


class InteropTestRunnerTest(unittest.TestCase):
  """
  Tests InteropTestRunner

  TODO(dlundberg): refactor code to test Create, CreateEncrypted, TestAll,
  GenerateAll, CreateKeys, DisplayTests
  """

  def setUp(self):
    self.runner = interop.InteropTestRunner(MockLogger())
    self.runner.algorithms = {
        "crypting": {
          "purpose": "crypt",
          "asymmetric": False,
          "keySizes": [128, 192, 256],
          "createFlags": ["--purpose=crypt"],
          "addKeyFlags": []
        },
        "signing": {
          "purpose": "sign",
          "asymmetric": False,
          "keySizes": [256],
          "createFlags": ["--purpose=sign"],
          "addKeyFlags": []
        },
        "crypting-asymmetric": {
          "purpose": "crypt",
          "asymmetric": True,
          "keySizes": [1024],
          "createFlags": ["--purpose=crypt", "--asymmetric=rsa"],
          "addKeyFlags": []
        }
    }
    self.runner.key_set_options = {
        "sign": {
          "generateOptions": {},
          "testOptions": {
            "signOption2": ["1", "2", "3"],
            "pubKey": [""]
          }
        },
        "crypt": {
          "generateOptions": {
            "cryptOption1": ["1", "2"],
            "pubKey": [""]
          },
          "testOptions": {
            "cryptOption2": ["1"]
          }
        },
        "verify": {
          "generateOptions": {},
          "testOptions": {
            "signOption2": ["1", "2"],
            "pubKey": ["public"]
          }
        },
        "encrypt": {
          "generateOptions": {
            "cryptOption1": ["1"],
            "pubKey": ["public"]
          },
          "testOptions": {
            "cryptOption2": ["1"]
          }
        }
    }
    self.runner.ignored_tests = []
    self.runner.operations = {
        "sign-operation": {
          "keytype": "sign",
          "generateOptions": {},
          "testOptions": {}
        },
        "encrypt-operation": {
          "keytype": "crypt",
          "generateOptions": {
            "operation-option": ["1", "2"]
          },
          "testOptions": {}
        }
    }

    self.runner.implementations = {
      "echo": ["echo"]
    }
    self.runner.macros = {}

  def testCallImplementation(self):
    # this command will error
    self.runner.implementations["err"] = ["python", "-c", "1/0"]

    for string in ("hello world!", "{}\n''"):
      out = self.runner._CallImplementation("echo", string)
      assert out.strip() == string.strip()
      try:
        self.runner._CallImplementation("err", string)
        assert False, "This should always throw an error"
      except Exception, e:
        pass

  def __GetAllExceptions(self):
    output = []
    for implementation in self.runner.implementations:
      for operation in self.runner.operations:
        purpose = self.runner.operations[operation]["keytype"]
        for keyset in interop.Keyset.GetGenerateKeysets(purpose, self.runner):
          for generates in self.runner._Options(
              operation, keyset, "generateOptions"):
            for tkeyset in interop.Keyset.GetTestKeysets(keyset, self.runner):
              for tests in self.runner._Options(
                  operation, tkeyset, "testOptions"):
                combined_options = dict(generates.items() + tests.items())
                if self.runner._IsException(
                    implementation, operation, keyset.name, combined_options):
                  output.append((
                      implementation, operation, keyset.name, combined_options))
    return output

  def testNoException(self):
    # Test that there are no exceptions
    assert len(self.__GetAllExceptions()) == 0, "Exception for ignored_tests={}"

  def testIgnoredAlgorithm(self):
    self.runner.ignored_tests = [
        {
          "implementation": ["*"],
          "operation": ["*"],
          "algorithm": ["crypt128"],
          "options": {"*": "*"},
          "reason": "Testing."
        }
    ]

    exceptions = self.__GetAllExceptions()
    for exception in exceptions:
      implementation, operation, algorithm, combined_options = exception
      assert algorithm == "crypt128"
    for params in self.runner._GenerateAll():
      generate_implementation, operation, keyset, generate_options = params
      assert keyset.name != "crypt128"

  def testIgnoredOperation(self):
    self.runner.ignored_tests = [
        {
          "implementation": ["*"],
          "operation": ["encrypt-operation"],
          "algorithm": ["*"],
          "options": {"*": "*"},
          "reason": "Testing."
        }
    ]

    exceptions = self.__GetAllExceptions()
    for exception in exceptions:
      implementation, operation, algorithm, combined_options = exception
      assert operation == "encrypt-operation"
    for params in self.runner._GenerateAll():
      generate_implementation, operation, keyset, generate_options = params
      assert operation != "encrypt-operation"

  def testIgnoredImplementation(self):
    self.runner.ignored_tests = [
        {
          "implementation": ["echo"],
          "operation": ["*"],
          "algorithm": ["*"],
          "options": {"*": "*"},
          "reason": "Testing."
        }
    ]

    exceptions = self.__GetAllExceptions()
    for exception in exceptions:
      implementation, operation, algorithm, combined_options = exception
      assert implementation == "echo"
    for params in self.runner._GenerateAll():
      generate_implementation, operation, keyset, generate_options = params
      assert generate_implementation != "echo"

  def testIgnoredOption(self):
    self.runner.ignored_tests = [
        {
          "implementation": ["*"],
          "operation": ["*"],
          "algorithm": ["*"],
          "options": {"operation-option": "1"},
          "reason": "Testing."
        }
    ]

    exceptions = self.__GetAllExceptions()
    for exception in exceptions:
      implementation, operation, algorithm, options = exception
      assert("operation-option" in options and
             "1" == options["operation-option"])
    for params in self.runner._GenerateAll():
      generate_implementation, operation, keyset, options = params
      if "operation-option" in options:
        assert "1" != options["operation-option"]

  def testGenerate(self):
    output = self.runner._Generate("echo", "encrypt-operation", "crypt128", {})
    json_dict = json.loads(output)
    assert json_dict["command"] == "generate"
    assert json_dict["operation"] == "encrypt-operation"
    assert json_dict["keyPath"] == "keys/echo"
    assert json_dict["algorithm"] == "crypt128"
    assert json_dict["generateOptions"] == {}
    assert json_dict["testData"] == interop.TESTDATA

  def testTest(self):
    output = self.runner._Test(
        "{\"output\": 1}", "echo", "echo",
        "encrypt-operation", "crypt128", {}, {})
    json_dict = json.loads(output)
    assert json_dict["command"] == "test"
    assert json_dict["operation"] == "encrypt-operation"
    assert json_dict["keyPath"] == "keys/echo"
    assert json_dict["algorithm"] == "crypt128"
    assert json_dict["generateOptions"] == {}
    assert json_dict["testOptions"] == {}
    assert json_dict["output"]["output"] == 1
    assert json_dict["testData"] == interop.TESTDATA

  def testSetupInteropTests(self):
    methods = dir(self.runner.InteropTest)
    self.runner.SetupInteropTests()
    methods_after_setup = dir(self.runner.InteropTest)

    count = 0
    for params in self.runner._GenerateAll():
      generate_implementation, operation, keyset, generate_options = params
      for test_implementation, test_options in self.runner._TestAll(
          operation, keyset, generate_options):
        count += 1

    assert len(methods_after_setup) - len(methods) == count

  def testGetKeyPath(self):
    assert "keys/echo" == self.runner._GetKeyPath("echo")

  def testGetKeyDir(self):
    assert "keys/echo/crypting" == self.runner._GetKeyDir("echo", "crypting")

  def __GetAllOptions(self, operation, keyset, option_string):
    return [op for op in self.runner._Options(operation, keyset, option_string)]

  def testOptions(self):
    key_set_options = self.runner.key_set_options
    keyset = interop.Keyset(key_set_options, "signing", 256, "sign")
    gen_ops = self.__GetAllOptions("sign-operation", keyset, "generateOptions")
    assert gen_ops == [{}]

    test_ops = self.__GetAllOptions("sign-operation", keyset, "testOptions")
    assert test_ops == [
        {"signOption2": "1", "pubKey": ""},
        {"signOption2": "2", "pubKey": ""},
        {"signOption2": "3", "pubKey": ""}]

    keyset = interop.Keyset(key_set_options, "crypting", 128, "crypt")
    gen_ops = self.__GetAllOptions(
        "encrypt-operation", keyset, "generateOptions")
    assert gen_ops == [
        {"cryptOption1": "1", "pubKey": "", "operation-option": "1"},
        {"cryptOption1": "1", "pubKey": "", "operation-option": "2"},
        {"cryptOption1": "2", "pubKey": "", "operation-option": "1"},
        {"cryptOption1": "2", "pubKey": "", "operation-option": "2"}]

    test_ops = self.__GetAllOptions("encrypt-operation", keyset, "testOptions")
    assert test_ops == [{"cryptOption2": "1"}]

  def testGetCreateFlags(self):
    flags = self.runner._GetCreateFlags("crypting", 128, "location")
    assert flags == [
        "create",
        "--name=crypting128",
        "--location=location",
        "--purpose=crypt"
        ]

  def testGetAddKeyFlags(self):
    flags = self.runner._GetAddKeyFlags("crypting", 128, "location", "--flag")
    assert flags == [
        "addkey",
        "--status=primary",
        "--size=128",
        "--location=location",
        "--flag"
        ]

  def testGetPubKeyFlags(self):
    flags = self.runner._GetPubKeyFlags("location", "--flag")
    assert flags == [
        "pubkey",
        "--destination=locationpublic",
        "--location=location",
        "--flag"
        ]


class KeySetTest(unittest.TestCase):

  def setUp(self):
    self.runner = interop.InteropTestRunner(MockLogger())
    self.runner.algorithms = {
        "crypting": {
          "purpose": "crypt",
          "asymmetric": False,
          "keySizes": [128, 192, 256],
          "createFlags": ["--purpose=crypt"],
          "addKeyFlags": []
        },
        "signing": {
          "purpose": "sign",
          "asymmetric": False,
          "keySizes": [256],
          "createFlags": ["--purpose=sign"],
          "addKeyFlags": []
        },
        "signing-asymmetric": {
          "purpose": "sign",
          "asymmetric": True,
          "keySizes": [1024],
          "createFlags": ["--purpose=sign", "--asymmetric=dsa"],
          "addKeyFlags": []
        },
        "crypting-asymmetric": {
          "purpose": "crypt",
          "asymmetric": True,
          "keySizes": [1024],
          "createFlags": ["--purpose=crypt", "--asymmetric=rsa"],
          "addKeyFlags": []
        }
    }
    self.runner.key_set_options = {
        "sign": {
          "generateOptions": {
            "signOption1": ["", "aes128"]
          },
          "testOptions": {
            "signOption2": ["verifier", "signer"]
          }
        },
        "crypt": {
          "generateOptions": {
            "cryptOption1": ["", "aes128"]
          },
          "testOptions": {
            "cryptOption2": ["", "aes128"]
          }
        },
        "verify": {
          "generateOptions": {
            "verifyOption1": ["", "aes128"]
          },
          "testOptions": {
            "verifyOption2": ["verifier"]
          }
        },
        "encrypt": {
          "generateOptions": {
            "encryptOption1": ["encrypter"]
          },
          "testOptions": {
            "encryptOption2": ["", "aes128"]
          }
        }
    }
    # Keyset doesn't access these:
    self.runner.ignored_tests = []
    self.runner.operations = {}
    self.runner.implementations = {}
    self.runner.macros = {}

  def __GenerateKeysets(self, purpose):
    return [keyset for keyset in
            interop.Keyset.GetGenerateKeysets(purpose, self.runner)]

  def __CheckKeyset(
      self, keyset, algorithm, purpose, size, generate_options, test_options):
    assert keyset.algorithm == algorithm
    assert keyset.purpose == purpose
    assert keyset.size == size
    assert len(keyset.test_options) == len(test_options)
    for option in keyset.test_options:
      assert option in test_options
    assert len(keyset.generate_options) == len(generate_options)
    for option in keyset.generate_options:
      assert option in generate_options

  def testCryptTestKeysets(self):
    keyset = interop.Keyset(
        self.runner.key_set_options, "crypting", 128, "crypt")
    test_keysets = interop.Keyset.GetTestKeysets(keyset, self.runner)
    assert len(test_keysets) == 1
    for keyset in test_keysets:
      self.__CheckKeyset(
          keyset, "crypting", "crypt", 128, ["cryptOption1"], ["cryptOption2"])

  def testEncryptTestKeysets(self):
    keyset = interop.Keyset(
        self.runner.key_set_options, "crypting", 128, "encrypt")
    test_keysets = interop.Keyset.GetTestKeysets(keyset, self.runner)
    assert len(test_keysets) == 1
    for keyset in test_keysets:
      self.__CheckKeyset(
          keyset, "crypting", "crypt", 128, ["cryptOption1"], ["cryptOption2"])

  def testSignTestKeysets(self):
    keyset = interop.Keyset(
        self.runner.key_set_options, "signing", 256, "sign")
    test_keysets = interop.Keyset.GetTestKeysets(keyset, self.runner)
    assert len(test_keysets) == 1
    for keyset in test_keysets:
      self.__CheckKeyset(
          keyset, "signing", "sign", 256, ["signOption1"], ["signOption2"])

  def testVerifyTestKeysets(self):
    keyset = interop.Keyset(
        self.runner.key_set_options, "signing-asymmetric", 1024, "sign")
    test_keysets = interop.Keyset.GetTestKeysets(keyset, self.runner)
    assert len(test_keysets) == 2
    assert test_keysets[0].purpose != test_keysets[1].purpose
    for keyset in test_keysets:
      if keyset.purpose == "sign":
        self.__CheckKeyset(
            keyset, "signing-asymmetric", "sign",
            1024, ["signOption1"], ["signOption2"])
      elif keyset.purpose == "verify":
        self.__CheckKeyset(
            keyset, "signing-asymmetric", "verify",
            1024, ["verifyOption1"], ["verifyOption2"])
      else:
        raise ValueError("%s is not a valid keyset purpose"%keyset.purpose)

  def testCryptGenerateKeysets(self):
    crypt_keysets = self.__GenerateKeysets("crypt")
    assert len(crypt_keysets) == 5
    different_checked = set()
    for keyset in crypt_keysets:
      if keyset.name == "crypting128":
        different_checked.add("crypting128")
        self.__CheckKeyset(
            keyset, "crypting", "crypt", 128,
            ["cryptOption1"], ["cryptOption2"])
      elif keyset.name == "crypting192":
        different_checked.add("crypting192")
        self.__CheckKeyset(
            keyset, "crypting", "crypt", 192,
            ["cryptOption1"], ["cryptOption2"])
      elif keyset.name == "crypting256":
        different_checked.add("crypting256")
        self.__CheckKeyset(
            keyset, "crypting", "crypt", 256,
            ["cryptOption1"], ["cryptOption2"])
      elif keyset.name == "crypting-asymmetric1024":
        if keyset.purpose == "crypt":
          different_checked.add("crypting-asymmetric1024crypt")
          self.__CheckKeyset(
              keyset, "crypting-asymmetric", "crypt", 1024,
              ["cryptOption1"], ["cryptOption2"])
        elif keyset.purpose == "encrypt":
          different_checked.add("crypting-asymmetric1024encrypt")
          self.__CheckKeyset(
              keyset, "crypting-asymmetric", "encrypt", 1024,
              ["encryptOption1"], ["encryptOption2"])
        else:
          raise ValueError("%s is not a valid keyset purpose"%keyset.purpose)
      else:
        raise ValueError("%s is not a valid name"%keyset.name)
    assert len(different_checked) == 5, str(different_checked)

  def testSignGenerateKeysets(self):
    sign_keysets = self.__GenerateKeysets("sign")
    assert len(sign_keysets) == 2
    assert sign_keysets[0].name != sign_keysets[1].name
    for keyset in sign_keysets:
      if keyset.name == "signing256":
        self.__CheckKeyset(
            keyset, "signing", "sign", 256,
            ["signOption1"], ["signOption2"])
      elif keyset.name == "signing-asymmetric1024":
        self.__CheckKeyset(
            keyset, "signing-asymmetric", "sign", 1024,
            ["signOption1"], ["signOption2"])
      else:
        raise ValueError("%s is not a valid name"%keyset.name)


def suite():
  alltests = unittest.TestSuite([
      unittest.TestLoader().loadTestsFromTestCase(KeySetTest),
      unittest.TestLoader().loadTestsFromTestCase(InteropTestRunnerTest)])
  return alltests

if __name__ == "__main__":
  unittest.main(defaultTest="suite")
