// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <keyczar/base/path_service.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>

namespace base {
  bool PathProvider(int key, FilePath* result);
#if defined(OS_WIN)
  bool PathProviderWin(int key, FilePath* result);
#elif defined(OS_MACOSX)
  bool PathProviderMac(int key, FilePath* result);
#elif defined(OS_LINUX)
  bool PathProviderLinux(int key, FilePath* result);
#elif defined(OS_BSD)
  bool PathProviderBSD(int key, FilePath* result);
#endif
}

namespace {

typedef bool (*ProviderFunc)(int, FilePath*);

struct PathData {
  ProviderFunc provider_base;
  ProviderFunc provider_arch;

  PathData() {
    provider_base = base::PathProvider;

#ifdef OS_WIN
    provider_arch = base::PathProviderWin;
#endif

#ifdef OS_MACOSX
    provider_arch = base::PathProviderMac;
#endif

#if defined(OS_LINUX)
    provider_arch = base::PathProviderLinux;
#endif

#if defined(OS_BSD)
    provider_arch = base::PathProviderBSD;
#endif
  }
};

}  // namespace

bool PathService::Get(int key, FilePath* result) {
  PathData pathdata;
  DCHECK(result);
  DCHECK(key >= base::DIR_CURRENT);

  // special case the current directory because it can never be cached
  if (key == base::DIR_CURRENT)
    return file_util::GetCurrentDirectory(result);

  FilePath path;

  if (!pathdata.provider_base(key, &path)) {
    DCHECK(path.empty()) << "provider should not have modified path";
    pathdata.provider_arch(key, &path);
  }

  if (path.empty())
    return false;

  *result = path;
  return true;
}

// static
bool PathService::Get(int key, std::wstring* result) {
  // Deprecated compatibility function.
  FilePath path;
  if (!Get(key, &path))
    return false;
  *result = path.ToWStringHack();
  return true;
}
