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

"""Test for command_output.  This is a MEDIUM test."""

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

  env = Environment(tools=['command_output'])

  # Make sure python is in the path, and set $PYTHON='python' so output will
  # compare exactly.
  env.PrependENVPath('PATH', env.File(sys.executable).dir.abspath)
  env.Replace(PYTHON='python',
              COMMAND_OUTPUT_CMDLINE='python $SOURCE')

  # Need to run our python program
  helloprog = env.File('hello.py')

  # Simple command
  env4 = env.Clone()
  env4.CommandOutput('out1.txt', helloprog)

  # Remaining commands not echoed
  # TODO: Setting this here seems to affect echoing for out1.txt, unless we
  # clone that environment?
  env['COMMAND_OUTPUT_ECHO'] = False

  # Command which doesn't exist
  env.CommandOutput('out2.txt', helloprog, COMMAND_OUTPUT_CMDLINE='nosuch.exe')

  # Command which fails.  Also verifies command line args are passed, and SCons
  # variables in command line are substituted.
  env.CommandOutput('out3.txt', helloprog,
                    COMMAND_OUTPUT_CMDLINE='python $SOURCE 3')

  # Command, output not echoed
  env.CommandOutput('out4.txt', helloprog)

  # Environment variables should be passed to the program
  env2 = env.Clone()
  env2['ENV']['VAR1'] = 'foo'
  env2.CommandOutput('out5.txt', helloprog)

  # Test specifying working directory
  subdir = env.Dir('sub1')
  # TODO: This highlights a weakness in the current CommandOutput().  Would be
  # nicer to specify the command line as '${SOURCE.abspath}', but that causes
  # an AttributeError exception.
  env3 = env.Clone()
  # Working directory will be added to the path and lib path.  Clear those
  # first to make comparison easier.
  env3['ENV']['PATH'] = ''
  env3['ENV']['LD_LIBRARY_PATH'] = ''
  # Need to explicitly specify python, since we won't find it in the path
  env3['PYTHON'] = sys.executable
  env3.CommandOutput('out6.txt', [], COMMAND_OUTPUT_RUN_DIR=subdir,
                     COMMAND_OUTPUT_CMDLINE='$PYTHON hello2.py')

  # Command with timeout
  env.CommandOutput('out7.txt', env.File('hello3.py'),
                    COMMAND_OUTPUT_ECHO=True,
                    COMMAND_OUTPUT_TIMEOUT=5,
                    COMMAND_OUTPUT_TIMEOUT_ERRORLEVEL=42)


hello_py_contents = """
import os
import sys
print 'Hello, world!  argc=%d' % len(sys.argv)
if 'VAR1' in os.environ:
  print 'VAR1 = %s' % os.environ['VAR1']
if len(sys.argv) > 1:
  sys.exit(int(sys.argv[1]))
"""

hello2_py_contents = """
import os
print 'PATH = %s' % os.environ['PATH']
print 'LD_LIBRARY_PATH = %s' % os.environ['LD_LIBRARY_PATH']
"""

hello3_py_contents = """
print 'La la la never going to die.'
while True:
  pass
"""

expect_stdout145 = """scons: Reading SConscript files ...
scons: done reading SConscript files.
scons: Building targets ...
Output "python hello.py" to out1.txt
Hello, world!  argc=1

Output "python hello.py" to out4.txt
Output "python hello.py" to out5.txt
scons: done building targets.
"""

expect_stdout2 = """scons: Reading SConscript files ...
scons: done reading SConscript files.
scons: Building targets ...
Output "nosuch.exe" to out2.txt
scons: building terminated because of errors.
"""

expect_stdout3 = """scons: Reading SConscript files ...
scons: done reading SConscript files.
scons: Building targets ...
Output "python hello.py 3" to out3.txt
scons: building terminated because of errors.
"""

expect_stdout7 = """scons: Reading SConscript files ...
scons: done reading SConscript files.
scons: Building targets ...
Output "python hello3.py" to out7.txt
*** RunCommand() timeout: python hello3.py

scons: building terminated because of errors.
"""


def main():
  test = TestFramework.TestFramework()

  # TODO: get this to work on windows and linux under coverage.
  if os.environ.get('COVERAGE_HOOK') and sys.platform in ('linux', 'linux2'):
    msg = 'Platform %s cannot run this test during coverage currently.\n'
    test.skip_test(msg % repr(sys.platform))
    return

  base = 'command_output'
  test.subdir(base)
  subdir1 = base + '/sub1'
  test.subdir(subdir1)

  test.WriteSConscript(base + '/SConstruct', TestSConstruct)
  test.write(base + '/hello.py', hello_py_contents)
  test.write(subdir1 + '/hello2.py', hello2_py_contents)
  test.write(base + '/hello3.py', hello3_py_contents)

  # Run build steps which should pass
  test.run(chdir=base, options='out1.txt out4.txt out5.txt',
           stdout=expect_stdout145)

  # Run build steps which should cause errors
  # Use match.re for the non-existent file test, since the error code is
  # different between platforms.
  test.run(chdir=base, options='out2.txt', match=test.match_re,
           stdout=expect_stdout2,
           stderr='scons: \*\*\* \[out2.txt\] Error [0-9]+\n', status=2)

  test.run(chdir=base, options='out3.txt', stdout=expect_stdout3,
           stderr='scons: *** [out3.txt] Error 3\n', status=2)

  # Test timeout
  test.run(chdir=base, options='out7.txt', stdout=expect_stdout7,
           stderr='scons: *** [out7.txt] Error 42\n', status=2)

  # Run build which runs command in a subdir
  test.run(chdir=base, options='out6.txt')

  # Check command output
  test.must_match(base + '/out1.txt', 'Hello, world!  argc=1\n')

  if sys.platform == 'win32':
    # On windows, know exactly what the error message should be.
    test.must_match(base + '/out2.txt', """\
'nosuch.exe' is not recognized as an internal or external command,
operable program or batch file.
""")
  else:
    # On other platforms, just make sure the output exists.
    test.must_exist(base + '/out2.txt')

  test.must_match(base + '/out3.txt', 'Hello, world!  argc=2\n')
  test.must_match(base + '/out4.txt', 'Hello, world!  argc=1\n')
  test.must_match(base + '/out5.txt', 'Hello, world!  argc=1\nVAR1 = foo\n')
  test.must_match(base + '/out6.txt', 'PATH = sub1\nLD_LIBRARY_PATH = sub1\n')
  test.pass_test()

if __name__ == '__main__':
  main()
