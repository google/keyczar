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

"""Test for defer dependency cycle detection.  These are MEDIUM tests."""

import SCons.Errors
import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']
  env = Environment(tools=['component_setup', 'defer'])

  #--------------------------------------
  # Test cycle detection

  def FuncA(env):
    env = env
    print 'FuncA'

  def FuncB(env):
    env = env
    print 'FuncB'

  def FuncC(env):
    env = env
    print 'FuncC'

  env.Defer(FuncA, after=FuncB)
  env.Defer(FuncB, after=FuncC)
  env.Defer(FuncC, after=FuncA)

  # Use try-except rather than letting SCons catch the exception, because SCons
  # puts the line number of the raise statement in the output, which is
  # fragile.
  try:
    env.ExecuteDefer()
  except SCons.Errors.UserError, msg:
    # Make sure the dependency cycle is printed, but the order of the lines in
    # the cycle doesn't matter.
    expect_msg = """Error in ExecuteDefer: dependency cycle detected.
   FuncA after: set(['FuncB'])
   FuncC after: set(['FuncA'])
   FuncB after: set(['FuncC'])
  """

    msglines = map(lambda s: s.strip(), str(msg).split('\n'))
    expectlines = map(lambda s: s.strip(), str(expect_msg).split('\n'))
    msglines.sort()
    expectlines.sort()
    if msglines == expectlines:
      print 'got expected exception'
    else:
      print 'Expected exception like:\n%s\ngot:\n%s\n' % (expect_msg, msg)


def main():
  test = TestFramework.TestFramework()

  test.subdir('defer')
  base = 'defer/'

  test.WriteSConscript(base + 'SConstruct', TestSConstruct)

  expect_stdout = """scons: Reading SConscript files ...
got expected exception
scons: done reading SConscript files.
scons: Building targets ...
scons: `scons-out' is up to date.
scons: done building targets.
"""

  test.run(chdir=base, stdout=expect_stdout)
  test.pass_test()


if __name__ == '__main__':
  main()
