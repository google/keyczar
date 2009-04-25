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

"""Test for including all tools.  These are SMALL tests."""


import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  env = Environment(tools=['component_setup'])

  # TODO: SDL and NACL tools generate an error if not installed.  Block this
  # error.
  env['SDL_MODE'] = 'none'
  env['NACL_SDK_VALIDATE'] = '0'

  # Make sure that all tools can at least be included without failure on all
  # platforms.
  all_tools = [
      'atlmfc_vc80',
      'code_coverage',
      'code_signing',
      'collada_dom',
      'command_output',
      'component_bits',
      'component_builders',
      'component_setup',
      'component_targets',
      'component_targets_msvs',
      'component_targets_xml',
      'concat_source',
      'defer',
      'directx_9_0_c',
      'directx_9_18_944_0_partial',
      'distcc',
      'environment_tools',
      'gather_inputs',
      'naclsdk',
      'publish',
      'replace_strings',
      'replicate',
      'sdl',
      'seven_zip',
      'target_debug',
      'target_optimized',
      'target_platform_linux',
      'target_platform_mac',
      'target_platform_windows',
      'visual_studio_solution',
      'windows_hard_link',
  ]
  for tool in all_tools:
    if tool not in env['TOOLS']:
      print 'Adding tool %s...' % tool
      # Not all tools play well together (for example, you can only use one of
      # the target_platform tools at a time), so put each in a separate
      # sub-environment
      env.Clone(tools=[tool])


def main():
  test = TestFramework.TestFramework()

  # Run tests
  base = 'all_tools/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.run(chdir=base)
  test.pass_test()

if __name__ == '__main__':
  main()
