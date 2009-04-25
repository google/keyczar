#!/usr/bin/python2.4
# Copyright 2009, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Testing framework for the software construction toolkit.

A TestFramework environment object is created via the usual invocation:

  import TestFramework
  test = TestFramework.TestFramework()

TestFramework is a subclass of TestCommon, which is in turn is a subclass
of TestCmd.
"""

import base64
import os
import re
import sys
import unittest

import TestCommon
import TestSCons


diff_re = TestCommon.diff_re
fail_test = TestCommon.fail_test
no_result = TestCommon.no_result
pass_test = TestCommon.pass_test
match_exact = TestCommon.match_exact
match_re = TestCommon.match_re
match_re_dotall = TestCommon.match_re_dotall
python_executable = TestCommon.python_executable

exe_suffix = TestCommon.exe_suffix
obj_suffix = TestCommon.obj_suffix
shobj_suffix = TestCommon.shobj_suffix
lib_prefix = TestCommon.lib_prefix
lib_suffix = TestCommon.lib_suffix
dll_prefix = TestCommon.dll_prefix
dll_suffix = TestCommon.dll_suffix

file_expr = TestSCons.file_expr


def RunUnitTests(testcase, **kwargs):
  """Runs all unit tests from a test case.

  Args:
    testcase: Test case class (derived from unittest.TestCase)
    kwargs: Optional variables to inject into each test case object.

  For example:
      RunUnitTests(MyToolTests, scons_globals=scons_globals, root_env=env)

  If a test fails, exits the program via sys.exit(3).
  """
  # Make the test suite
  suite = unittest.makeSuite(testcase)

  # Inject variables into each test
  for t in suite._tests:
    for k, v in kwargs.items():
      setattr(t, k, v)

  # Run test
  result = unittest.TextTestRunner(verbosity=2).run(suite)
  if not result.wasSuccessful():
    # A unit test failed
    sys.exit(3)


class TestFramework(TestCommon.TestCommon):
  """Class for testing this framework.

  Default behavior is to test hammer.bat on Windows or hammer.sh on
  any other type of system.

  A temporary directory gets created (we chdir there) and will be removed
  automatically when we exit.
  """

  def __init__(self, *args, **kw):

    # If they haven't specified that they want to test some other
    # explicit program, either in the TestFramework() object creation or
    # by setting the $TEST_FRAMEWORK_EXE / %TEST_FRAMEWORK_EXE% environment
    # variable, then we test 'hammer.bat' on Windows systems and 'hammer.sh'
    # everywhere else.
    if not 'program' in kw:
      kw['program'] = os.environ.get('TEST_FRAMEWORK_EXE')
      if not kw['program']:
        if sys.platform == 'win32':
          kw['program'] = 'hammer.bat'
        else:
          kw['program'] = os.getcwd() + '/hammer.sh'

    # Pass in the magic workdir value '', which will cause a temporary
    # directory to be created and get us chdir'ed there--but save
    # the original cwd first in case we need to know where we were...
    if not 'workdir' in kw:
      kw['workdir'] = ''

    TestCommon.TestCommon.__init__(self, *args, **kw)

    # Use our match function, so we don't need to worry about trailing
    # whitespace on output we want to compare.
    self.match = self.match_visible

  def FakeWindowsCER(self, filename):
    """Write out a fake windows certificate."""
    # Generated with:
    # makecert.exe -r -sv fake.pvk -n "CN=fakeco" fake.cer (password: secret)
    self.write(filename, base64.b64decode("""
MIIB7TCCAVagAwIBAgIQcInZW/UOFodA41ESSHTYuzANBgkqhkiG9w0BAQQFADARMQ8wDQYDVQQD
EwZmYWtlY28wHhcNMDgwNTA3MjAyNjI2WhcNMzkxMjMxMjM1OTU5WjARMQ8wDQYDVQQDEwZmYWtl
Y28wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANERhPhli6dLzhU3xFO81uVPrluufLF9lqF6
tNCN4cX+5JaDWZzjiX+fHR/M+8od6f2VXZ6fML9uIq/8cWOQL/oqfKbX7R/MWCvOzsrpI7iLJu4Z
uYl+VhUWt3bxjl7bfH89NOS5cZhGuF7z/nVS0J0yconFhkFs6IBp3dKMuHMhAgMBAAGjRjBEMEIG
A1UdAQQ7MDmAELq4xibLMx3dvWmlZHSr8S2hEzARMQ8wDQYDVQQDEwZmYWtlY2+CEHCJ2Vv1DhaH
QONREkh02LswDQYJKoZIhvcNAQEEBQADgYEARvV1vBoIoP1DZosFVr11HLgKhffKhXxh8XfFLxd1
JMJc/j8x0iNlW3IcVWNeDxh8x3TTJYODTM9WPXi2PL/Ouw2dPToYRnS5vP31EoXGLYlvp1sxnyzo
LLE9zUGKBTvHeaWVjHhDh66dWS9ss6pXcVrElSgZVlBTg6jZgvxV27A=
"""))

  def FakeWindowsPVK(self, filename):
    """Write out a fake private key file."""
    # Generated with:
    # makecert.exe -r -sv fake.pvk -n "CN=fakeco" fake.cer (password: secret)
    self.write(filename, base64.b64decode("""
HvG1sAAAAAACAAAAAQAAABAAAABUAgAAHXQX+j2ePmaFlOVCODMBigcCAAAAJAAA6tHDlTGLFBkD
JbgKswhpzNuqXFUxW3ZYGQb5oH9wy5UCpIddroTpfpM8y7PMz1YWCJ2ijqIdAksv3qc9pV5xlRyF
YalQoLXPn9wklkYMbl2zBQAXnDgCy3JWa07tjCIMelieKQNzsCkTHq3iPpuF/IeL+q8o0AtxizK/
SeKLVc3VXH9F6L3pIKFud0UwvFD2Phea8OhWkTsRdz9kQTKXgW2ScIhEqea9w04jY/7bOJJB9JzQ
75beIS3inuKD7r/Ynf2VJzI+AGY0Zkyq48Pmjx9yGBuMId0T4o8K4pSfQiWc5NLfLP6Jz7IzAUHW
+r+9X/8p84IA5YNMeWYommfxjwHl6r0R4UOQaA2hseoq+Tqf6B6lfuWYCrZl7u8D/VYvyYWlImWg
G3jJyRUwDKAyZ6/hTdGU7mlcRPMjAvg4CyWQCp9CLT4JziRxEaoQWbKQLDcVIGMqmytqujbuZBtl
hR1v571uD7daAW8iKPhjkaBjAALa7kmzDIS8DY7YuMAmvV7stzBW8q/eLakmN9UWnlmpDHeCEmuj
tjXhDIONv7j63So8W3B5umRJMD8eM4rC0/9Pu1e2BVlPc6J5Dgo1ZGCKmdtb8zzv0Ea7xlc2ZLU+
lqdiYR6DgsEH6gvjLzYK491yQMCbC9l9lOwhLHTGrtHsXKZyM4Puid3ODAkHlMZy4D9feWakVhpS
DmB7w6ikflbPvsx200M9FMbXkcXkT6LMFmye4D8uCaooPYJDrBLVFi9gbAXtRj8WJ2+hRefzG5+N
pEUUTCf3tuiV
"""))

  def FakeWindowsPFX(self, filename):
    """Write out a fake windows certificate + private key file."""
    # Generated using:
    # makecert.exe -r -sv fake.pvk -n "CN=fakeco" fake.cer (password: secret)
    # pvk2pfx.exe -pvk fake.pvk -spc fake.cer -pfx fake.pfx -po obscure
    self.write(filename, base64.b64decode("""
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
"""))

  def match_visible(self, str1, str2):
    """Returns true if the strings look the same.

    Args:
      str1: First string to compare.
      str2: Seconds string to compare.

    Returns:
      True if the strings are the same, after stripping trailing whitespace
      from lines.  That is, if they look them same when printed to a terminal.
    """
    # Add a newline at end of the strings, in case strings have trailing
    # whitespace but no newline at the end.
    str1 = re.sub('[ \t\r]*\n', '\n', str1 + '\n')
    str2 = re.sub('[ \t\r]*\n', '\n', str2 + '\n')
    return str1 == str2

  def WriteSConscript(self, filename, function, python_paths=None):
    """Writes a SConscript which will call the function.

    Args:
      filename: Destination filename.
      function: Function to call from SConscript.  This will be passed the
          globals() dict from the SConscript.
      python_paths: List of additional python paths to include in sys.path
          for SConscript.

    If the function needs access to SCons functions or variables, it should
    get them from the passed globals dict:

    def MySConscript(scons_globals):
      Environment = scons_globals['Environment']
      ...

    Returns:
      Passthrough return from self.write().
    """

    if python_paths is None:
      python_paths = []

    func_path, func_file = os.path.split(function.func_code.co_filename)

    python_paths += [
        # Directory containing the module with the function to call
        func_path,
        # Directory containing THIS module, since the module calling it most
        # likely imports it, and the path to the TestCommon module, since this
        # file imports it.
        os.path.dirname(__file__),
        os.path.dirname(TestCommon.__file__),
    ]

    data = ('# SConscript file '
            'automatically created by TestFramework.WriteSConscript().\n'
            'import sys\n')

    for p in python_paths:
      # Need to turn backslashes into forward-slashes, since we're writing a
      # string into a python source file.  (Could alternately double-up the
      # backslashes.)
      data += 'sys.path.append("%s")\n' % p.replace('\\', '/')

    data += 'from %s import %s\n%s(globals())\n' % (
        os.path.splitext(func_file)[0],
        function.__name__,
        function.__name__
    )

    return self.write(filename, data)

