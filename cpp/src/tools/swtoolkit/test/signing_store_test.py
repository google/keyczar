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

"""Test for code signing from the signing store.  This is a MEDIUM test."""

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

  # Replace default signing tool with a command to echo the signing command
  # line to the target.
  env['SIGNTOOL'] = 'echo >"$TARGET" signtool'

  env.SignedBinary('hello_signed.exe', 'hello_unsigned.exe')
  env.SignedBinary('hello_signed2.exe', 'hello_unsigned.exe',
                   CERTIFICATE_STORE='other store')


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

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript)
  test.write(base + 'hello_unsigned.exe', 'This is a fake exe.')

  # Run SCons.
  test.run(chdir=base, arguments=['--certificate-name=my cert'])

  # Check signing from default store.
  expected_cmd = (' signtool sign /s "my" /n "my cert"'
                  ' /t "http://timestamp.verisign.com/scripts/timestamp.dll"'
                  ' "scons-out\sign\obj\hello_signed.exe"\n')
  test.must_match(base_out + 'hello_signed.exe', expected_cmd)

  # Check signing from alternate store.
  expected_cmd = (' signtool sign /s "other store" /n "my cert"'
                  ' /t "http://timestamp.verisign.com/scripts/timestamp.dll"'
                  ' "scons-out\sign\obj\hello_signed2.exe"\n')
  test.must_match(base_out + 'hello_signed2.exe', expected_cmd)

  test.pass_test()


if __name__ == '__main__':
  main()
