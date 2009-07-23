// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KEYCZAR_BASE_BASE_PATHS_H_
#define KEYCZAR_BASE_BASE_PATHS_H_

// This file declares path keys for the base module.  These can be used with
// the PathService to access various special directories and files.

#include <keyczar/base/basictypes.h>
#if defined(OS_WIN)
#include <keyczar/base/base_paths_win.h>
#elif defined(OS_MACOSX)
#include <keyczar/base/base_paths_mac.h>
#elif defined(OS_LINUX)
#include <keyczar/base/base_paths_linux.h>
#elif defined(OS_BSD)
#include <keyczar/base/base_paths_bsd.h>
#endif
#include <keyczar/base/path_service.h>

namespace base {

enum {
  PATH_START = 0,

  DIR_CURRENT,  // current directory
  DIR_EXE,      // directory containing FILE_EXE
  DIR_MODULE,   // directory containing FILE_MODULE
  DIR_TEMP,     // temporary directory
  PATH_END
};

}  // namespace base

#endif  // KEYCZAR_BASE_BASE_PATHS_H_

