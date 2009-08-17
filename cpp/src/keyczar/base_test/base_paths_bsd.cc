// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copied and adapted from base/base_paths_linux.cc

#include <keyczar/base_test/base_paths_bsd.h>

// FreeBSD and NetBSD have a getprogname() function, OpenBSD has not.
#if defined(__OpenBSD__)
extern const char* __progname;
#define getprogname() (__progname)
#endif
#include <stdlib.h>
#include <unistd.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base_test/path_service.h>

namespace keyczar {
namespace base_test {

bool GetTempDir(FilePath* path) {
  const char* tmp = getenv("TMPDIR");
  if (tmp)
    *path = FilePath(tmp);
  else
    *path = FilePath("/tmp");
  return true;
}

bool PathProviderBSD(int key, FilePath* result) {
  FilePath path;
  switch (key) {
    case FILE_EXE:
    case FILE_MODULE: {
      *result = FilePath(getprogname());
      return true;
    }
    case DIR_SOURCE_ROOT: {
      // On *BSD, unit tests execute three levels deep from the source root.
      // For example:  scons-out/<target>/tests/base_unittests
      if (!PathService::Get(DIR_EXE, &path))
        return false;
      path = path.Append(FilePath::kParentDirectory);
      path = path.Append(FilePath::kParentDirectory);
      path = path.Append(FilePath::kParentDirectory);
      *result = path;
      return true;
    }
    default:
      return false;
  }
  return false;
}

}  // namespace base_test
}  // namespace keyczar
