#!/usr/bin/python2.4
#
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

# Significant portions of this script are lifted from:
#
# runtest.py - wrapper script for running SCons tests
# Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 The SCons Foundation
#

"""Wrapper script for running tests.  Use 'runtest.py -h' to print usage."""


import glob
import os
import optparse
import re
import subprocess
import sys
import time


OPTION_LIST = [
    optparse.make_option(
        "-a", "--all", action="store_true", dest="all", default=False,
        help=("Run all tests; does a virtual 'find' for all tests under "
              "the current directory."),
    ),
    optparse.make_option(
        "-d", "--debug",
        action="store_true", dest="debug", default=False,
        help=("Runs the script under the Python debugger "
              "(pdb.py) so you don't have to muck with PYTHONPATH yourself."),
    ),
    optparse.make_option(
        "-f", "--file", dest="testlistfile", metavar="FILE", default=None,
        help="Only execute the tests listed in the specified FILE.",
    ),
    optparse.make_option(
        "--ignore-no-result",
        action="store_false", dest="fail_on_no_result", default=True,
        help="Don't return 2 on tests with no result.",
    ),
    optparse.make_option(
        "-q", "--quiet",
        action="store_true", dest="quiet", default=False,
        help=("By default, runtest.py prints the command line "
              "it will execute before executing it.  This suppresses "
              "that print."),
    ),
    optparse.make_option(
        "-t", "--time",
        action="store_true", dest="time", default=False,
        help="Print the execution time of each test.",
    ),
    optparse.make_option(
        "-l", "--list",
        action="store_true", dest="list_only", default=False,
        help="List available tests and exit.",
    ),
    optparse.make_option(
        "-n", "--no-exec",
        action="store_false", dest="execute_tests", default=True,
        help="No execute, just print command lines.",
    ),
    optparse.make_option(
        "-P", dest="python", metavar="PYTHON", default=None,
        help="Use the specified PYTHON interpreter.",
    ),
    optparse.make_option(
        "-F", dest="pythonflags", metavar="FLAG", default=[], type="string",
        action="append",
        help=("Pass the specified FLAG to python.  May be specified multiple "
              "times to pass multiple flags.")
    ),
    optparse.make_option(
        "--verbose", dest="verbose", metavar="LEVEL",
        help=("Set verbose level: "
              "1 = print executed commands. "
              "2 = print commands and non-zero output. "
              "3 = print commands and all output."),
    ),
    optparse.make_option(
        "--passed",
        action="store_true", dest="passed_summary", default=False,
        help=("In the final summary, also report which tests passed. "
              "The default is to only report tests which failed or "
              "returned NO RESULT."),
    ),
]


class Error(Exception):
  """Local Error class."""
  pass


class Unbuffered:
  """Class for flushing after every write()."""

  def __init__(self, filehandle):
    self.filehandle = filehandle

  def write(self, arg):
    """Write the specified arg and flush()."""
    self.filehandle.write(arg)
    self.filehandle.flush()

  def __getattr__(self, attr):
    return getattr(self.filehandle, attr)


class Test:
  """An individual test."""

  command = ["python"]
  common_args = []
  _ws_expr = re.compile("\s")

  EXIT_SUCCESS = 0
  EXIT_FAILED = 1
  EXIT_NO_RESULT = 2

  def __init__(self, path):
    """Test initialization.

    Args:
      path:  the path to the test being executed/recorded
    """
    self.path = path
    self.abspath = os.path.abspath(path)
    self.status = None
    self.test_args = []

  def Execute(self):
    """Execute the test command line."""
    self.status = subprocess.call(self.GetCommandStr(), shell=True)
    if self.status < 0 or self.status > 2:
      sys.stdout.write("Unexpected exit status %d\n" % self.status)

  def GetCommandArgs(self):
    """Return the complete command-line arguments as a list."""
    return self.command + self.common_args + self.test_args

  def GetCommandStr(self):
    """Return the command-line as a string, suitable for display."""
    return " ".join(map(self.Quote, self.GetCommandArgs()))

  def Quote(self, s):
    """Return a quoted version of a string if it has white space.

    Args:
      s: The input string.

    Returns:
      The quoted string if it contains white space, or the original if not.
    """
    if self._ws_expr.search(s):
      s = '"' + s + '"'
    return s


def main():
  parser = optparse.OptionParser(option_list=OPTION_LIST)
  opts, args = parser.parse_args()

  if opts.quiet:
    print_command = lambda s: None
  else:
    print_command = lambda s: sys.stdout.write(s)

  if opts.time:
    print_time = lambda fmt, time: sys.stdout.write(fmt % time)
  else:
    print_time = lambda fmt, time: None

  if opts.debug:
    for d in sys.path:
      pdb = os.path.join(d, "pdb.py")
      if os.path.exists(pdb):
        debug = pdb
        break
  else:
    debug = ""

  testlistfile = opts.testlistfile
  if testlistfile:
    testlistfile = os.path.abspath(testlistfile)

  if opts.verbose:
    os.environ['TESTCMD_VERBOSE'] = opts.verbose

  if not args and not opts.all and not testlistfile and not opts.list_only:
    parser.print_help()
    parser.error('No tests were specified')
    return 1

  if not sys.stdout.isatty():
    sys.stdout = Unbuffered(sys.stdout)

  python = opts.python
  if not python:
    if os.name == "java":
      python = os.path.join(sys.prefix, "jython")
    else:
      python = sys.executable

  Test.command = [python]
  Test.common_args = opts.pythonflags

  # Need SCONS_DEV_DIR environment variable to point to the root of a
  # SCons source (scons-src) package, so that we can use its QMTest modules.
  scons_dev_dir = os.environ.get("SCONS_DEV_DIR")
  if not scons_dev_dir:
    parser.error('SCONS_DEV_DIR environment variable not set.')
    return 1
  scons_dir = os.path.join(scons_dev_dir, "src", "engine")

  cwd = os.getcwd()
  test_dir = os.path.join(cwd, "test")

  pythonpaths = [
      os.path.join(cwd, "lib"),
      os.path.join(cwd, "site_scons"),
      os.path.join(scons_dev_dir, "QMTest"),
      scons_dir,
  ]

  old_pythonpath = os.environ.get("PYTHONPATH")
  if old_pythonpath:
    pythonpaths.append(old_pythonpath)

  os.environ["PYTHONPATH"] = os.pathsep.join(pythonpaths)
  os.environ["SCONS_DIR"] = scons_dir

  tests = []

  if args:
    for a in args:
      tests.extend(glob.glob(a))
  elif testlistfile:
    for line in open(testlistfile, "r"):
      line = line.strip()
      if line and line[0] != "#":
        tests.append(line)
  elif opts.all or opts.list_only:

    def FindPy(tests, dirname, names):
      """Add any .py files to the list of tests.

      Passed to os.path.walk() to find all the .py files, and conforms
      to the calling signature for os.path.walk() callbacks.

      Args:
        tests: list in which we're accumulating python files
        dirname: directory we're examining
        names: the entries in that directory
      """
      python_names = [n for n in names if n[-3:].lower() == ".py"]
      tests.extend([os.path.join(dirname, n) for n in python_names])

    os.path.walk(test_dir, FindPy, tests)
    tests.sort()

  tests = [Test(t) for t in tests]

  if opts.list_only:
    # Print tests in a format which can be passed back in using --file
    sys.stdout.write("# runtest found the following tests:\n")
    for t in tests:
      sys.stdout.write("  %s\n" % t.abspath)
    sys.stdout.write("\n")
    return 0

  # time.clock() is the suggested interface for doing benchmarking
  # timings, but time.time() does a better job on Linux systems, so let
  # that be the non-Windows default.

  if sys.platform == "win32":
    time_func = time.clock
  else:
    time_func = time.time

  total_start_time = time_func()

  for t in tests:
    if debug:
      t.test_args.append(debug)
    t.test_args.append(t.abspath)
    print_command(t.GetCommandStr() + ": ")
    test_start_time = time_func()
    if opts.execute_tests:
      t.Execute()
    t.test_time = time_func() - test_start_time
    print_time("Test execution time: %.1f seconds\n", t.test_time)

  if tests:
    tests[0].total_time = time_func() - total_start_time
    fmt = "Total execution time for all tests: %.1f seconds\n"
    print_time(fmt, tests[0].total_time)

  passed = [t for t in tests if t.status == t.EXIT_SUCCESS]
  failed = [t for t in tests if t.status == t.EXIT_FAILED]
  no_result = [t for t in tests if t.status == t.EXIT_NO_RESULT]

  if len(tests) != 1 and opts.execute_tests:

    def PrintResults(result_list, result_string):
      """Common function for printing different types of test results.

      Args:
        result_list: the list of tests that {passed, failed, no result}
        result_string: a string to print describing the type of results
      """
      if not result_list:
        return
      l = len(result_list)
      if l == 1:
        s = "\n%s the following test:\n" % result_string
      else:
        s = "\n%s the following %d tests:\n" % (result_string, l)
      sys.stdout.write(s)
      paths = [x.path for x in result_list]
      sys.stdout.write("\t" + "\n\t".join(paths) + "\n")

    if opts.passed_summary:
      PrintResults(passed, "Passed")
    PrintResults(failed, "Failed")
    PrintResults(no_result, "NO RESULT from")

  if failed:
    return 1
  elif no_result and opts.fail_on_no_result:
    return 2
  else:
    return 0

if __name__ == "__main__":
  sys.exit(main())
