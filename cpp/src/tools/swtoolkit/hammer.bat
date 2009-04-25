@echo off
::=============================================================================
:: hammer.bat - Hammer wrapper for software construction toolkit for SCons
::
:: Copyright 2009, Google Inc.
:: All rights reserved.
::
:: Redistribution and use in source and binary forms, with or without
:: modification, are permitted provided that the following conditions are
:: met:
::
::     * Redistributions of source code must retain the above copyright
:: notice, this list of conditions and the following disclaimer.
::     * Redistributions in binary form must reproduce the above
:: copyright notice, this list of conditions and the following disclaimer
:: in the documentation and/or other materials provided with the
:: distribution.
::     * Neither the name of Google Inc. nor the names of its
:: contributors may be used to endorse or promote products derived from
:: this software without specific prior written permission.
::
:: THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
:: "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
:: LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
:: A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
:: OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
:: SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
:: LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
:: DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
:: THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
:: (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
:: OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
::
:: Environment variables used all the time:
::   HAMMER_OPTS        Command line options for hammer/SCons, in addition to
::                      any specified on the command line.
::
:: Environment variables used for IncrediBuild (Xoreax Grid Engine) support:
::   HAMMER_XGE         If set to 1, enable IncrediBuild
::   HAMMER_XGE_PATH    Path to IncrediBuild install.  Required if it was not
::                      installed in the default location
::                      (%ProgramFiles%\Xoreax\IncrediBuild).
::   HAMMER_XGE_OPTS    Additional options to pass to IncrediBuild.
::
:: Sample values for HAMMER_OPTS:
::   -j%NUMBER_OF_PROCESSORS%
::      Run parallel builds on all processor cores, unless explicitly
::      overridden on the command line.
::   -j12
::      Always run 12 builds in parallel; a good default if HAMMER_XGE=1.
::   -s -k
::      Don't print commands; keep going on build failures.

::=============================================================================
:: Hammer setup

setlocal

:: Append SCONS_DIR to the python path
set PYTHONPATH=%PYTHONPATH%;%SCONS_DIR%

:: Specify site_scons directories
set HAMMER_OPTS=%HAMMER_OPTS% --site-dir="%~dp0site_scons"

:: Run SCons via software construction toolkit wrapper.
set HAMMER_CMD=python -x %COVERAGE_HOOK% "%~dp0wrapper.py" %HAMMER_OPTS% %*

:: ============================================================================
:: Incredibuild support

if not defined HAMMER_XGE set HAMMER_XGE=0
if %HAMMER_XGE% neq 1 goto END_XGE_SETUP

:: Allow IncrediBuild to intercept tools run by python; run cl remotely.
set HAMMER_XGE_OPTS=%HAMMER_XGE_OPTS% /allowintercept=python /allowremote=cl

:: Add IncrediBuild back into the path (from the default location, if not
:: explicitly specified)
if not defined HAMMER_XGE_PATH (
  set HAMMER_XGE_PATH="%ProgramFiles%\Xoreax\IncrediBuild"
)
set XGCONSOLE_PATH=%HAMMER_XGE_PATH%\xgConsole.exe
if not exist %XGCONSOLE_PATH% (
  echo Warning: xgConsole.exe not found in %HAMMER_XGE_PATH%
  echo Not using IncrediBuild.
  goto END_XGE_SETUP
)
set PATH=%PATH%;%HAMMER_XGE_PATH%

:: Use IncrediBuild to wrap the call to python.
set HAMMER_CMD=XGConsole.exe %HAMMER_XGE_OPTS% /command="%HAMMER_CMD%"

:END_XGE_SETUP
:: ============================================================================
:: Run whatever command we came up with

%HAMMER_CMD%
