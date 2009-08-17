// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyczar/base_test/path_service.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/string_util.h>

namespace keyczar {
namespace base_test {
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
}  // namespace base_test
}  // namespace keyczar

namespace {

typedef bool (*ProviderFunc)(int, FilePath*);

struct PathData {
  ProviderFunc provider_base;
  ProviderFunc provider_arch;

  PathData() {
    provider_base = keyczar::base_test::PathProvider;

#ifdef OS_WIN
    provider_arch = keyczar::base_test::PathProviderWin;
#endif

#ifdef OS_MACOSX
    provider_arch = keyczar::base_test::PathProviderMac;
#endif

#if defined(OS_LINUX)
    provider_arch = keyczar::base_test::PathProviderLinux;
#endif

#if defined(OS_BSD)
    provider_arch = keyczar::base_test::PathProviderBSD;
#endif
  }
};

}  // namespace

namespace keyczar {
namespace base_test {

bool PathService::Get(int key, FilePath* result) {
  PathData pathdata;
  DCHECK(result);

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

}  // namespace base_test
}  // namespace keyczar
