// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copied and adapted from base/base_paths_linux.cc

#include <keyczar/base/base_paths_bsd.h>

// FreeBSD and NetBSD have a getprogname() function, OpenBSD has not.
#if defined(__OpenBSD__)
extern const char* __progname;
#define getprogname() (__progname)
#else  // !OpenBSD
#include <stdlib.h>
#endif

#include <keyczar/base/file_path.h>
#include <keyczar/base/path_service.h>

namespace base {

bool PathProviderBSD(int key, FilePath* result) {
  FilePath path;
  switch (key) {
    case base::FILE_EXE:
    case base::FILE_MODULE: {
      *result = FilePath(getprogname());
      return true;
    }
    case base::DIR_SOURCE_ROOT:
      // On *BSD, unit tests execute three levels deep from the source root.
      // For example:  scons-out/<target>/tests/base_unittests
      if (!PathService::Get(base::DIR_EXE, &path))
        return false;
      path = path.Append(FilePath::kParentDirectory);
      path = path.Append(FilePath::kParentDirectory);
      path = path.Append(FilePath::kParentDirectory);
      *result = path;
      return true;
  }
  return false;
}

}  // namespace base

