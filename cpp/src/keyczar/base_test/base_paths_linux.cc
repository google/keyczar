// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base_test/base_paths_linux.h>

#include <stdlib.h>
#include <unistd.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/logging.h>
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

bool PathProviderLinux(int key, FilePath* result) {
  FilePath path;
  switch (key) {
    case FILE_EXE:
    case FILE_MODULE: {
      char bin_dir[PATH_MAX + 1];
      int bin_dir_size = readlink("/proc/self/exe", bin_dir, PATH_MAX);
      if (bin_dir_size < 0 || bin_dir_size > PATH_MAX) {
        NOTREACHED() << "Unable to resolve /proc/self/exe.";
        return false;
      }
      bin_dir[bin_dir_size] = 0;
      *result = FilePath(bin_dir);
      return true;
    }
    case DIR_SOURCE_ROOT: {
      // On linux, unit tests execute three levels deep from the source root.
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
