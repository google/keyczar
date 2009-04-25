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

"""Test for code signing.  This is a LARGE test."""

import sys
import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(
      tools=['component_setup', 'target_platform_windows', 'code_signing'],
      BUILD_TYPE='sign',
      BUILD_TYPE_DESCRIPTION='Signing build',
  )
  env.Append(
      BUILD_GROUPS=['default'],
      BUILD_COMPONENTS=['SConscript'],
  )
  BuildComponents([env])


def TestSConscript(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  prog = env.Program('hello.exe', 'hello.c')
  env.SignedBinary('hello_unsigned.exe', prog)
  env.SignedBinary('hello_signed.exe', prog,
                   CERTIFICATE_PATH='fake.pfx',
                   CERTIFICATE_PASSWORD='obscure')


hello_c_contents = """
#include <stdio.h>

int main() {
  printf("Hello, world!\\n");
}
"""


def main():
  test = TestFramework.TestFramework()

  platforms_with_signing = ['win32', 'cygwin']

  if sys.platform not in platforms_with_signing:
    msg = 'Platform %s does not support signing; skipping test.\n'
    test.skip_test(msg % repr(sys.platform))
    return 0

  test.subdir('signing')

  base = 'signing/'
  base_out = base + 'scons-out/sign/obj/'

  test.FakeWindowsPFX(base + 'fake.pfx')
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript)
  test.write(base + 'hello.c', hello_c_contents)

  # Run SCons.
  test.run(chdir=base)
  # Check for test output.
  test.must_exist(base_out + 'hello.exe')
  test.must_exist(base_out + 'hello_unsigned.exe')
  test.must_exist(base_out + 'hello_signed.exe')
  # Test output must be runnable.
  test.run(program=test.workpath(base_out + 'hello.exe'),
           stdout='Hello, world!\n')
  test.run(program=test.workpath(base_out + 'hello_signed.exe'),
           stdout='Hello, world!\n')
  test.run(program=test.workpath(base_out + 'hello_unsigned.exe'),
           stdout='Hello, world!\n')
  # By default signing is a pass thru, so these two should match.
  if (test.read(base_out + 'hello.exe') !=
      test.read(base_out + 'hello_unsigned.exe')):
    test.fail_test()
  # Signed version should not match.
  if (test.read(base_out + 'hello.exe') ==
      test.read(base_out + 'hello_signed.exe')):
    test.fail_test()

  # Cover certificate with junk.
  test.write(base + 'fake.pfx', 'blahblah!\n')
  # Run SCons, expecting failure.
  test.run(chdir=base, stderr=None, status=2)
  test.fail_test(test.stderr().find('SignTool Error') == -1)

  test.pass_test()


if __name__ == '__main__':
  main()
