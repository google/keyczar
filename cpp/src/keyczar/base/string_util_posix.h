// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KEYCZAR_BASE_STRING_UTIL_POSIX_H_
#define KEYCZAR_BASE_STRING_UTIL_POSIX_H_

#include <stdarg.h>
#include <stdio.h>

#include <keyczar/base/logging.h>

namespace base {

inline int vsnprintf(char* buffer, size_t size,
                     const char* format, va_list arguments) {
  return ::vsnprintf(buffer, size, format, arguments);
}

}  // namespace base

#endif  // KEYCZAR_BASE_STRING_UTIL_POSIX_H_

