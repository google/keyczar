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

"""Component targets MSVS test (MEDIUM test)."""

import sys
import TestFramework


def TestSConstruct(scons_globals):
  """Test SConstruct file.

  Args:
    scons_globals: Global variables dict from the SConscript file.
  """

  # Get globals from SCons
  Environment = scons_globals['Environment']

  base_env = Environment(tools=['component_setup'])
  base_env.Append(BUILD_COMPONENTS=['SConscript'])

  windows_env = base_env.Clone(
      tools=['target_platform_windows', 'component_targets_msvs'],
      BUILD_TYPE='dbg',
      BUILD_TYPE_DESCRIPTION='Debug Windows build',
  )
  windows_env.Append(BUILD_GROUPS=['default'])

  BuildComponents([windows_env])

  # Dir source project
  p = windows_env.ComponentVSDirProject(
      'client_source',
      ['$MAIN_DIR'],
      COMPONENT_VS_SOURCE_FOLDERS=[
          # Files are assigned to first matching folder.  Folder names of None
          # are filters.
          (None, '$DESTINATION_ROOT'),
          ('bar', '$MAIN_DIR/bar'),
          ('main', '$MAIN_DIR'),
      ],
      # Force source project to main dir, so that Visual Studio can find the
      # source files corresponding to build errors.
      COMPONENT_VS_PROJECT_DIR='$MAIN_DIR',
  )

  # DAG-scanning source project
  p += windows_env.ComponentVSSourceProject('foo2', ['foo'])

  # Solution and target projects
  windows_env.ComponentVSSolution(
      'test_sln',
      [
          'all_libraries',
          'all_programs',
          'all_test_programs',
      ],
      projects=[p],
  )


sconscript_contents = """
Import('env')

env.ComponentProgram('hello', 'hello.c')
env.ComponentLibrary('foo', 'foo.c')
"""

hello_c_contents = """
#include <stdio.h>

int main() {
  printf("Hello, world!\\n");
  return 0;
}
"""

foo_c_contents = """
int test(int a, int b) {
  return a + b;
}
"""

expected_sln = r"""Microsoft Visual Studio Solution File, Format Version 9.00
# Visual Studio 2005
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "foo", "projects\foo.vcproj", "{45AB06CB-52ED-E345-2A58-10362CDF360A}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "hello", "projects\hello.vcproj", "{632417AE-F599-CD9F-918B-A17075835EC8}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "client_source", "..\..\client_source.vcproj", "{1B67F18C-880F-E270-F356-FA884FA5D74F}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "foo2", "projects\foo2.vcproj", "{5C29244F-CABC-F552-B86D-A7E99D74D682}"
EndProject
Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "all_libraries", "all_libraries", "{D38FD69F-C7D6-9F66-E16B-E2B5A5399371}"
EndProject
Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "all_programs", "all_programs", "{EE92F063-A834-C3AB-3F99-E760B318B3C3}"
EndProject
Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "all_test_programs", "all_test_programs", "{6185A63C-DC88-A7CA-D49B-205276B0508D}"
EndProject
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		dbg|Win32 = dbg|Win32
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{45AB06CB-52ED-E345-2A58-10362CDF360A}.dbg|Win32.ActiveCfg = dbg|Win32
		{632417AE-F599-CD9F-918B-A17075835EC8}.dbg|Win32.ActiveCfg = dbg|Win32
		{1B67F18C-880F-E270-F356-FA884FA5D74F}.dbg|Win32.ActiveCfg = dbg|Win32
		{5C29244F-CABC-F552-B86D-A7E99D74D682}.dbg|Win32.ActiveCfg = dbg|Win32
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
	GlobalSection(NestedProjects) = preSolution
		{45AB06CB-52ED-E345-2A58-10362CDF360A} = {D38FD69F-C7D6-9F66-E16B-E2B5A5399371}
		{632417AE-F599-CD9F-918B-A17075835EC8} = {EE92F063-A834-C3AB-3F99-E760B318B3C3}
	EndGlobalSection
EndGlobal
"""

expected_foo_vcproj = r"""<?xml version="1.0" encoding="Windows-1252"?>
<VisualStudioProject Keyword="MakeFileProj" Name="foo" ProjectGUID="{45AB06CB-52ED-E345-2A58-10362CDF360A}" ProjectType="Visual C++" RootNamespace="foo" Version="8.00">
  <Platforms>
    <Platform Name="Win32"/>
  </Platforms>
  <ToolFiles/>
  <Configurations>
    <Configuration ConfigurationType="0" IntermediateDirectory="$(ProjectDir)/dbg/foo/tmp" Name="dbg|Win32" OutputDirectory="$(ProjectDir)/dbg/foo/out">
      <Tool AssemblySearchPath="" BuildCommandLine="$(ProjectDir)/../../../hammer.bat --mode=dbg foo" CleanCommandLine="$(ProjectDir)/../../../hammer.bat --mode=dbg -c foo" CompileAsManaged="" ForcedIncludes="" ForcedUsingAssemblies="" IncludeSearchPath="" Name="VCNMakeTool" Output="../../../foo.lib" PreprocessorDefinitions="" ReBuildCommandLine="$(ProjectDir)/../../../hammer.bat --mode=dbg -c foo &amp;&amp; $(ProjectDir)/../../../hammer.bat --mode=dbg foo"/>
    </Configuration>
  </Configurations>
  <Files/>
  <Globals/>
</VisualStudioProject>
"""

expected_client_source = r"""<?xml version="1.0" encoding="Windows-1252"?>
<VisualStudioProject Keyword="MakeFileProj" Name="client_source" ProjectGUID="{1B67F18C-880F-E270-F356-FA884FA5D74F}" ProjectType="Visual C++" RootNamespace="client_source" Version="8.00">
  <Platforms>
    <Platform Name="Win32"/>
  </Platforms>
  <ToolFiles/>
  <Configurations>
    <Configuration ConfigurationType="0" Name="all|Win32">
      <Tool AssemblySearchPath="" CompileAsManaged="" ForcedIncludes="" ForcedUsingAssemblies="" IncludeSearchPath="" Name="VCNMakeTool" PreprocessorDefinitions=""/>
    </Configuration>
  </Configurations>
  <Files>
    <Filter Name="bar">
      <File RelativePath="bar\bar.cpp"/>
    </Filter>
    <Filter Name="main">
      <File RelativePath="foo.c"/>
      <File RelativePath="hello.c"/>
    </Filter>
  </Files>
  <Globals/>
</VisualStudioProject>
"""

expected_foo2_vcproj = r"""<?xml version="1.0" encoding="Windows-1252"?>
<VisualStudioProject Keyword="MakeFileProj" Name="foo2" ProjectGUID="{5C29244F-CABC-F552-B86D-A7E99D74D682}" ProjectType="Visual C++" RootNamespace="foo2" Version="8.00">
  <Platforms>
    <Platform Name="Win32"/>
  </Platforms>
  <ToolFiles/>
  <Configurations>
    <Configuration ConfigurationType="0" Name="all|Win32">
      <Tool AssemblySearchPath="" CompileAsManaged="" ForcedIncludes="" ForcedUsingAssemblies="" IncludeSearchPath="" Name="VCNMakeTool" PreprocessorDefinitions=""/>
    </Configuration>
  </Configurations>
  <Files>
    <Filter Name="source">
      <File RelativePath="..\..\..\foo.c"/>
    </Filter>
  </Files>
  <Globals/>
</VisualStudioProject>
"""

def main():
  test = TestFramework.TestFramework()

  # Test only applies to Windows
  if sys.platform not in ('win32', 'cygwin'):
    test.skip_test('This test only applies to windows.\n')
    return

  base = 'hello/'
  test.subdir(base)
  test.WriteSConscript(base + 'SConstruct', TestSConstruct)
  test.write(base + 'SConscript', sconscript_contents)
  test.write(base + 'hello.c', hello_c_contents)
  test.write(base + 'foo.c', foo_c_contents)
  test.subdir(base + 'bar')
  test.write(base + 'bar/bar.cpp', foo_c_contents)

  test.run(chdir=base, options='test_sln')

  # Check that all solutions and projects were generated.
  test.must_exist(base + 'scons-out/solution/test_sln.sln')
  test.must_exist(base + 'client_source.vcproj')
  test.must_exist(base + 'scons-out/solution/projects/foo.vcproj')
  test.must_exist(base + 'scons-out/solution/projects/foo2.vcproj')
  test.must_exist(base + 'scons-out/solution/projects/hello.vcproj')

  # Check file output for each type.  We can do this because the GUIDs are
  # deterministic.
  test.must_match(base + 'scons-out/solution/test_sln.sln', expected_sln)
  test.must_match(base + 'scons-out/solution/projects/foo.vcproj',
                  expected_foo_vcproj)
  test.must_match(base + 'scons-out/solution/projects/foo2.vcproj',
                  expected_foo2_vcproj)
  test.must_match(base + 'client_source.vcproj', expected_client_source)

  test.pass_test()

if __name__ == '__main__':
  main()
