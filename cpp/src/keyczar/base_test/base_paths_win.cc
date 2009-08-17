// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base_test/base_paths_win.h>

#include <windows.h>
#include <shlobj.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base_test/path_service.h>

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace keyczar {
namespace base_test {

bool GetTempDir(FilePath* path) {
  wchar_t temp_path[MAX_PATH + 1];
  DWORD path_len = ::GetTempPath(MAX_PATH, temp_path);
  if (path_len >= MAX_PATH || path_len <= 0)
    return false;
  // TODO(evanm): the old behavior of this function was to always strip the
  // trailing slash.  We duplicate this here, but it shouldn't be necessary
  // when everyone is using the appropriate FilePath APIs.
  std::wstring path_str(temp_path);
  TrimTrailingSeparator(&path_str);
  *path = FilePath(path_str);
  return true;
}

bool PathProviderWin(int key, FilePath* result) {
  // We need to go compute the value. It would be nice to support paths with
  // names longer than MAX_PATH, but the system functions don't seem to be
  // designed for it either, with the exception of GetTempPath (but other
  // things will surely break if the temp path is too long, so we don't bother
  // handling it.
  wchar_t system_buffer[MAX_PATH];
  system_buffer[0] = 0;

  FilePath cur;
  switch (key) {
    case FILE_EXE:
      GetModuleFileName(NULL, system_buffer, MAX_PATH);
      cur = FilePath(system_buffer);
      break;
    case FILE_MODULE: {
      // the resource containing module is assumed to be the one that
      // this code lives in, whether that's a dll or exe
      HMODULE this_module = reinterpret_cast<HMODULE>(&__ImageBase);
      GetModuleFileName(this_module, system_buffer, MAX_PATH);
      cur = FilePath(system_buffer);
      break;
    }
    case DIR_SOURCE_ROOT: {
      // On Windows, unit tests execute three levels deep from the source root.
      // For example:  chrome/{Debug|Release}/ui_tests.exe
      PathService::Get(DIR_EXE, &cur);
      cur = cur.Append(FilePath::kParentDirectory);
      cur = cur.Append(FilePath::kParentDirectory);
      cur = cur.Append(FilePath::kParentDirectory);
      break;
    }
    default:
      return false;
  }

  *result = cur;
  return true;
}

}  // namespace base_test
}  // namespace keyczar


