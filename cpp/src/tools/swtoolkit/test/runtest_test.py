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

"""Test runtest (hey, recursion!) (MEDIUM TEST)."""

import TestFramework
import os
import sys


expect_stdout = """usage: runtest.py [options]

options:
  -a, --all             Run all tests; does a virtual 'find' for all tests
                        under the current directory.
  -d, --debug           Runs the script under the Python debugger (pdb.py) so
                        you don't have to muck with PYTHONPATH yourself.
  -f FILE, --file=FILE  Only execute the tests listed in the specified FILE.
  --ignore-no-result    Don't return 2 on tests with no result.
  -q, --quiet           By default, runtest.py prints the command line it will
                        execute before executing it.  This suppresses that
                        print.
  -t, --time            Print the execution time of each test.
  -l, --list            List available tests and exit.
  -n, --no-exec         No execute, just print command lines.
  -P PYTHON             Use the specified PYTHON interpreter.
  -F FLAG               Pass the specified FLAG to python.  May be specified
                        multiple times to pass multiple flags.
  --verbose=LEVEL       Set verbose level: 1 = print executed commands. 2 =
                        print commands and non-zero output. 3 = print commands
                        and all output.
  --passed              In the final summary, also report which tests passed.
                        The default is to only report tests which failed or
                        returned NO RESULT.
  -h, --help            show this help message and exit
"""


dummy_test_contents = """
import TestFramework


def main():
  print 'running dummy test'
  test = TestFramework.TestFramework()
  test.pass_test()
  return 0


if __name__ == '__main__':
  main()
"""

other_py_contents = """
import sys
print 'other.py got arg="%s"' % sys.argv[1]
"""


def main():

  # Test runtest itself, rather than scons
  runtest = '%s %s/bin/runtest.py ' % (
      os.environ.get('COVERAGE_HOOK', ''), os.getcwd())
  # Convert test args to a list, so we can add args with spaces below
  runtest = runtest.split()

  test = TestFramework.TestFramework(program=sys.executable)

  base = 'runtest/'
  test.subdir(base)
  test.write('dummy_test.py', dummy_test_contents)
  test.write('other.py', other_py_contents)

  # On mac, help output is slightly different
  if sys.platform == 'darwin':
    global expect_stdout
    expect_stdout = expect_stdout.replace('usage:', 'Usage:')
    expect_stdout = expect_stdout.replace('options:', 'Options:')

  # Check help
  test.run(arguments=runtest + ['--help'], stdout=expect_stdout)

  # Check running itself but doing nothing
  test.run(arguments=runtest + ['-n', '-a'])

  # Run a dummy test
  test.run(arguments=runtest + ['dummy_test.py'], stderr='PASSED\n')
  test.fail_test(test.stdout().find('running dummy test') == -1)

  # Check -F arguments
  test.run(arguments=runtest + ['-Fother.py', '-F', '1 2 3', 'dummy_test.py'])
  # Should not have run the test
  test.fail_test(test.stdout().find('running dummy test') != -1)
  # Should have the second -F arg, all as one param
  test.fail_test(test.stdout().find('other.py got arg="1 2 3"') == -1)

  # Check fake cert creation routines in TestFramework
  test.FakeWindowsCER(base + 'fake1.cer')
  test.must_exist(base + 'fake1.cer')

  test.FakeWindowsPVK(base + 'fake1.pvk')
  test.must_exist(base + 'fake1.pvk')

  test.FakeWindowsPFX(base + 'fake1.pfx')
  test.must_exist(base + 'fake1.pfx')

  test.pass_test()

  return 0


if __name__ == '__main__':
  main()
