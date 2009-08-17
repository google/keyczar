// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base_test/base_paths.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base_test/path_service.h>

namespace keyczar {
namespace base_test {

bool PathProvider(int key, FilePath* result) {
  FilePath cur;
  switch (key) {
    case DIR_EXE: {
      PathService::Get(FILE_EXE, &cur);
      cur = cur.DirName();
      break;
    }
    case DIR_MODULE: {
      PathService::Get(FILE_MODULE, &cur);
      cur = cur.DirName();
      break;
    }
    case DIR_TEMP: {
      return GetTempDir(result);
    }
    default:
      return false;
  }

  *result = cur;
  return true;
}

}  // namespace base_test
}  // namespace keyczar
