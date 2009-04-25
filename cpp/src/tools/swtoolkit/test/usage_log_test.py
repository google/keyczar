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

"""Test for usage_log.  These are SMALL tests."""


import unittest
import xml.dom.minidom
import TestFramework
import usage_log

#------------------------------------------------------------------------------


class UsageLogLogTests(unittest.TestCase):
  """Tests for usage_log.Log class."""

  def MockDumpWriter(self, log):
    """Mock dump writer.

    Args:
      log: Logfile passed to Dump().
    """
    self.dumped_log = log
    self.dumped_entries = list(log.entries)

  def MockTime(self):
    """Amok Time function (Spock needs a girlfriend).

    Returns:
      A time value popped off of the start of self.mock_times.
    """
    return self.mock_times.pop(0)

  def setUp(self):
    """Per-test setup."""
    self.mock_times = [1, 4, 9, 16, 25]
    self.dumped_log = None
    self.dumped_entries = None

    self.log = usage_log.Log()
    # Inject mock time
    self.log.time = self.MockTime

  def testInit(self):
    """Test __init__()."""
    log = self.log
    self.assertEqual(log.params, {})
    self.assertEqual(log.entries, [])
    self.assert_(log.dump_writer is None)

  def testSetParam(self):
    """Test SetParam()."""
    log = self.log

    log.SetParam('foo', 'bar')
    log.SetParam('apple', 'berry')
    log.SetParam('apple', 'cherry')
    self.assertEqual(log.params, {'foo': 'bar', 'apple': 'cherry'})

  def testAddEntry(self):
    """Test AddEntry()."""
    log = self.log

    log.AddEntry('able')
    log.AddEntry('baker')
    log.AddEntry('baker')

    entry_texts = [e[1] for e in log.entries]
    self.assertEqual(entry_texts, ['able', 'baker', 'baker'])

    entry_times = [e[0] for e in log.entries]
    self.assertEqual(entry_times, [1, 4, 9])

  def testDumpNoWriter(self):
    """Test Dump() with no writer."""
    log = self.log

    log.AddEntry('foo')
    log.AddEntry('bar')

    log.Dump()
    # Log is cleared after dump, even if no writer
    self.assertEqual(log.entries, [])

  def testDumpWriter(self):
    """Test Dump() with a writer."""
    log = self.log

    # Add an entry and parameter before setting the dump writer
    log.AddEntry('foo')
    log.SetParam('apple', 'berry')

    # Hook in our dump writer
    log.dump_writer = self.MockDumpWriter

    # Add another entry and dump
    log.AddEntry('bar')
    pre_dump_entries = list(log.entries)
    log.Dump()

    # Make sure we were passed the correct log
    self.assert_(self.dumped_log is self.log)

    # Check contents at time of dump
    self.assertEqual(pre_dump_entries, self.dumped_entries)
    self.assertEqual(self.dumped_entries, [(1, 'foo'), (4, 'bar')])

    # Entries are cleared, params aren't
    self.assertEqual(log.entries, [])
    self.assertEqual(log.params, {'apple': 'berry'})

  def testConvertToXml(self):
    """Test converting log to XML."""
    log = self.log

    # Add some parameters
    log.SetParam('sneezy', False)
    log.SetParam('sleepy', 1)
    log.SetParam('grumpy', 'no coffee')
    log.SetParam('dwarves', ['short', 3, True])
    log.SetParam('birds', ('tweet', 'tweet'))

    # Add some entries
    log.AddEntry('dopey')
    log.AddEntry('bashful')

    # Convert to XML
    got_xml = log.ConvertToXml().toxml()

    # Launder expected XML through minidom so formatting and attribute order
    # is consistent with the generated XML.
    expected_xml = (
        '<?xml version="1.0" ?><usage_log><param_list><param name="birds">'
        '<item value="tweet"/><item value="tweet"/></param>'
        '<param name="dwarves"><item value="short"/><item value="3"/>'
        '<item value="True"/></param><param name="grumpy" value="no coffee"/>'
        '<param name="sleepy" value="1"/><param name="sneezy" value="False"/>'
        '</param_list><entry_list><entry text="dopey" time="1"/>'
        '<entry text="bashful" time="4"/></entry_list></usage_log>')
    want_xml = xml.dom.minidom.parseString(expected_xml).toxml()
    self.assertEqual(got_xml, want_xml)

  def testSetOutputFile(self):
    """Test SetOutputFile()."""
    log = self.log

    log.SetOutputFile('foo.xml')
    self.assertEqual(log.dump_to_file, 'foo.xml')
    self.assertEqual(log.dump_writer, usage_log.FileDumpWriter)

#------------------------------------------------------------------------------


class ProgressDisplayWrapperTests(unittest.TestCase):
  """Tests for usage_log.ProgressDisplayWrapper."""

  class MockDisplay(object):
    """Mock display object."""

    def __init__(self):
      self.call_text = ''
      self.append_newline = 41
      self.returnval = 42
      self.mode = 43

    def __call__(self, text, append_newline):
      self.call_text = text
      self.append_newline = append_newline
      return self.returnval

    def set_mode(self, mode):
      self.mode = mode
      return self.returnval

  def testProgressDisplayWrapper(self):
    """Test ProgressDisplayWrapper."""

    md = self.MockDisplay()
    p = usage_log.ProgressDisplayWrapper(md)

    md.returnval = 'foo'
    self.assertEqual(p.set_mode('bar'), 'foo')
    self.assertEqual(md.mode, 'bar')

    md.returnval = 'baz'
    self.assertEqual(p('sometext', 88), 'baz')
    self.assertEqual(md.call_text, 'sometext')
    self.assertEqual(md.append_newline, 88)
    self.assertEqual(usage_log.log.entries[-1][1], 'progress sometext')

#------------------------------------------------------------------------------


class UsageLogMethodTests(unittest.TestCase):
  """Tests for usage_log module methods."""

  class MockCmd(object):
    """Mock command object."""

    def __init__(self):
      """Constructor."""
      self.lastcmd = None

  def MockDumpWriter(self, log):
    """Mock dump writer.

    Args:
      log: Logfile passed to Dump().
    """
    self.dumped_entries = list(log.entries)

  def setUp(self):
    """Per-test setup."""
    self.dumped_entries = None

    # Back up usage_log globals
    self.old_log = usage_log.log
    self.old_chain = usage_log.chain_build_targets

    # Use our own log object
    usage_log.log = usage_log.Log()
    usage_log.log.dump_writer = self.MockDumpWriter

  def tearDown(self):
    """Per-test teardown."""
    usage_log.log = self.old_log
    usage_log.chain_build_targets = self.old_chain

  def testPrecmdWrapper(self):
    """Test PrecmdWrapper()."""
    cmd = self.MockCmd()
    usage_log.PrecmdWrapper(cmd, 'veni vidi visa')
    self.assertEqual(usage_log.log.entries[0][1], 'Interactive start')
    self.assertEqual(usage_log.log.params['interactive.command'],
                     'veni vidi visa')

  def testPrecmdWrapper2(self):
    """Test PrecmdWrapper() when no command is specified."""
    cmd = self.MockCmd()
    cmd.lastcmd = 'charge!'
    usage_log.PrecmdWrapper(cmd, '')
    self.assertEqual(usage_log.log.entries[0][1], 'Interactive start')
    self.assertEqual(usage_log.log.params['interactive.command'], 'charge!')

  def testPostcmdWrapper(self):
    """Test PostCmdWrapper()."""
    self.assertEqual(usage_log.PostcmdWrapper(1, True, 3), True)
    self.assertEqual(self.dumped_entries[0][1], 'Interactive done')

  def testAtExit(self):
    """Test AtExit()."""
    usage_log.AtExit()
    self.assertEqual(self.dumped_entries[0][1], 'usage_log exit')

  def testAddSystemParams(self):
    """Test AddSystemParams()."""
    usage_log.log.params.clear()
    usage_log.AddSystemParams()
    self.assertEqual(sorted(usage_log.log.params.keys()),
                     ['platform.platform',
                      'platform.uname',
                      'scons.version',
                      'shell.HAMMER_OPTS',
                      'shell.HAMMER_XGE',
                      'shell.INCLUDE',
                      'shell.LIB',
                      'shell.PATH',
                      'sys.argv',
                      'sys.executable',
                      'sys.path',
                      'sys.platform',
                      'sys.version',
                      'sys.version_info'])

  def testFileDumpWriter(self):
    """Test FileDumpWriter()."""

    class MockDoc(object):
      """Mock xml.dom.minidom.doc object."""

      def __init__(self):
        self.writeargs = None
        self.unlinked = False

      def writexml(self, f, encoding, addindent, newl):
        self.writeargs = (encoding, addindent, newl)
        f.write('pretend XML')

      def unlink(self):
        self.unlinked = True

    class MockLog(object):
      """Mock log object."""

      def __init__(self):
        self.dump_to_file = 'foo.xml'
        self.doc = MockDoc()

      def ConvertToXml(self):
        return self.doc

    # Dump the mock log
    l = MockLog()
    usage_log.FileDumpWriter(l)

    # Check calls
    self.assertEqual(l.doc.writeargs, ('UTF-8', '  ', '\n'))
    self.assertEqual(l.doc.unlinked, True)

    # Check XML contents
    f = open('foo.xml')
    gotxml = f.read()
    f.close()
    self.assertEqual(gotxml, 'pretend XML')

  def testBuildTargetsWrapper(self):
    """Test BuildTargetsWrapper()."""
    chain_args = []

    def MockChain(*args):
      """Mock chain_build_targets() call."""
      chain_args[:] = args

    class MockOptions(object):
      """Mock options object."""

      def __init__(self):
        """Constructor.  Sets up some options."""
        self.settable = 'settable'
        self.__foo = '__foo'
        self.funcptr = MockChain
        self.int_opt = 3
        self.str_opt = 'phoo'
        self.__SConscript_settings__ = {'int_opt': 2, 'int_scons': 4,
                                        'str_scons': 'qwerty'}

    usage_log.chain_build_targets = MockChain
    opts = MockOptions()
    usage_log.BuildTargetsWrapper('fs', opts, ['targ1', 123], 'top')

    self.assertEqual(usage_log.log.params, {
        'build_targets.option._MockOptions__foo': '__foo',
        'build_targets.option.str_scons': 'qwerty',
        'build_targets.option.int_opt': 3,
        'build_targets.option.str_opt': 'phoo',
        'build_targets.option.int_scons': 4,
        'build_targets.targets': ['targ1', '123']
    })
    self.assertEqual(chain_args, ['fs', opts, ['targ1', 123], 'top'])
    self.assertEqual(usage_log.log.entries[0][1], 'build_targets start')
    self.assertEqual(usage_log.log.entries[1][1], 'build_targets done')


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """
  # Run unit tests
  TestFramework.RunUnitTests(UsageLogLogTests)
  TestFramework.RunUnitTests(ProgressDisplayWrapperTests)
  TestFramework.RunUnitTests(UsageLogMethodTests)


def main():
  test = TestFramework.TestFramework()
  base = 'usage_log/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.run(chdir=base, stderr=None)
  test.pass_test()

if __name__ == '__main__':
  main()
