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

"""Test for code coverage.  This is a MEDIUM test."""

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

  base_env = Environment(
      tools=['component_setup'],
      COMPONENT_TEST_CMDLINE='echo run test',
      DESTINATION_ROOT='SCONS_OUT',
      PRE_EVALUATE_DIRS=[],
  )
  base_env.Append(
      BUILD_GROUPS=['default'],
      BUILD_COMPONENTS=['SConscript'],
  )

  environment_list = []

  # TODO: this has bad behavior on mac if linux and windows environments are
  # generated.
  if sys.platform != 'darwin':
    windows_env = base_env.Clone(
        tools=['target_platform_windows',
               'target_debug',
               'code_coverage'],
        BUILD_TYPE='coverage',
        BUILD_TYPE_DESCRIPTION='Code coverage windows build',

        CXX='echo >$TARGET',
        LINK='echo >$TARGET',
        MANIFEST_FILE=False,
        COVERAGE_ANALYZER='COVERAGE_ANALYZER',
        COVERAGE_ANALYZER_DIR='COVERAGE_ANALYZER_DIR',
        COVERAGE_VSPERFCMD='vsperfcmd',
        COVERAGE_VSINSTR='echo >>step_log.txt vsinstr',
    )
    # Convert coverage start steps to echos.
    start_cmd = windows_env['COVERAGE_START_CMD']
    start_cmd = ['echo >>step_log.txt ' + i for i in start_cmd]
    windows_env['COVERAGE_START_CMD'] = start_cmd
    # Convert coverage final steps to echos.
    # Drop last command (a copy), because it is not a string.
    stop_cmd = windows_env['COVERAGE_STOP_CMD']
    stop_cmd = stop_cmd[:-1]
    stop_cmd = ['echo >>step_log.txt ' + i for i in stop_cmd]
    windows_env['COVERAGE_STOP_CMD'] = stop_cmd
    environment_list.append(windows_env)

    linux_env = base_env.Clone(
        tools=['target_platform_linux',
               'target_debug',
               'code_coverage'],
        BUILD_TYPE='coverage',
        BUILD_TYPE_DESCRIPTION='Code coverage linux build',

        CXX='echo >$TARGET',
        COVERAGE_MCOV='echo >>step_log.txt mcov',
        COVERAGE_GENHTML='echo >>step_log.txt genhtml',
    )
    environment_list.append(linux_env)

  mac_env = base_env.Clone(
      tools=['target_platform_mac',
             'target_debug',
             'code_coverage'],
      BUILD_TYPE='coverage',
      BUILD_TYPE_DESCRIPTION='Code coverage mac build',

      CXX='echo >$TARGET',
      COVERAGE_MCOV='echo >>step_log.txt mcov',
      COVERAGE_GENHTML='echo >>step_log.txt genhtml',
  )
  environment_list.append(mac_env)

  BuildComponents(environment_list)


def TestSConscript(scons_globals):
  """Test SConscript file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Get globals from SCons
  scons_globals['Import']('env')
  env = scons_globals['env']

  env.ComponentTestProgram('hello_test', 'hello_test.cc')


def main():
  test = TestFramework.TestFramework()

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
        ' -vsperfcmd -shutdown\n'
        ' vsperfcmd -start:coverage '
        '-output:SCONS_OUT/coverage/coverage/coverage.lcov.pre\n'
        ' vsinstr /COVERAGE "SCONS_OUT\\coverage\\tests\\hello_test.exe"\n'
        ' -vsperfcmd -shutdown\n'
        ' c:\\Windows\\System32\\regsvr32.exe '
        '/S COVERAGE_ANALYZER_DIR/msdia80.dll\n'
        ' COVERAGE_ANALYZER '
        '-sym_path=. SCONS_OUT/coverage/coverage/coverage.lcov.pre.coverage\n'
        ' c:\\Windows\\System32\\regsvr32.exe /S /U '
        'COVERAGE_ANALYZER_DIR/msdia80.dll\n'
    )
  else:
    expected = (
        'mcov --directory SCONS_OUT/coverage '
        '--output SCONS_OUT/coverage/coverage/coverage.lcov\n'
        'genhtml --output-directory '
        'SCONS_OUT/coverage/coverage/html '
        'SCONS_OUT/coverage/coverage/coverage.lcov\n'
    )
  test.must_match(base + 'step_log.txt', expected)

  test.pass_test()


if __name__ == '__main__':
  main()
