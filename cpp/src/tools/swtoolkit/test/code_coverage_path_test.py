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

"""Test for code coverage $COVERAGE_INSTRUMENTATION_PATH on windows.

This is a MEDIUM test.
"""

import os
import sys
import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  Environment = scons_globals['Environment']

  windows_env = Environment(
      tools=['component_setup',
             'target_platform_windows',
             'target_debug',
             'code_coverage'],
      BUILD_TYPE='coverage',
      BUILD_TYPE_DESCRIPTION='Code coverage windows build',

      COMPONENT_TEST_CMDLINE='echo run test',

      CXX='echo >$TARGET',
      LINK='echo >$TARGET',
      MANIFEST_FILE=False,
      COVERAGE_ANALYZER_DIR='echo COVERAGE_ANALYZER_DIR',
      COVERAGE_VSPERFCMD='echo vsperfcmd',
      COVERAGE_VSINSTR='echo >>step_log.txt vsinstr',
      COVERAGE_START_CMD=['echo start'],
      COVERAGE_STOP_CMD=['echo stop'],
  )
  windows_env.Append(
      BUILD_GROUPS=['default'],
      BUILD_COMPONENTS=['SConscript'],
  )

  # So other platforms have a coverage and bob targets.
  windows_env.Alias('coverage')
  windows_env.Alias('bob')

  BuildComponents([windows_env])


def TestSConscript(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  prog = env.ComponentTestProgram('hello_test', 'hello_test.cc')
  env.Alias('bob', [
      env.Replicate('$ARTIFACTS_DIR', prog[0]),
      env.Replicate('$DESTINATION_ROOT/nocoverage', prog[0]),
  ])


def main():
  test = TestFramework.TestFramework()

  # TODO: get this to work on windows under coverage.
  # TODO: seems to be flaky on windows and linux
  if (os.environ.get('COVERAGE_HOOK') and
      sys.platform in ['win32', 'cygwin', 'linux', 'linux2']):
    msg = 'Platform %s cannot run this test during coverage currently.\n'
    test.skip_test(msg % repr(sys.platform))
    return

  test.subdir('coverage_test')

  base = 'coverage_test/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.WriteSConscript(base + 'SConscript', TestSConscript)
  test.write(base + 'hello_test.cc', 'This is a fake source file.')

  # Blank step log.
  test.write(base + 'step_log.txt', '')

  # Run SCons.
  test.run(chdir=base, arguments='coverage')

  # Check resulting step log.
  if sys.platform in ['win32', 'cygwin']:
    expected = (
        ' vsinstr /COVERAGE "scons-out\\coverage\\tests\\hello_test.exe"\n'
    )
    test.must_match(base + 'step_log.txt', expected)

  # Run SCons.
  test.run(chdir=base, arguments='bob')

  # Check resulting step log.
  if sys.platform in ['win32', 'cygwin']:
    expected = (
        ' vsinstr /COVERAGE "scons-out\\coverage\\tests\\hello_test.exe"\n'
        ' vsinstr /COVERAGE "scons-out\\coverage\\artifacts\\hello_test.exe"\n'
    )
    test.must_match(base + 'step_log.txt', expected)

  test.pass_test()


if __name__ == '__main__':
  main()
