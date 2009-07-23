// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KEYCZAR_BASE_STRING_UTIL_POSIX_H_
#define KEYCZAR_BASE_STRING_UTIL_POSIX_H_

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include <keyczar/base/logging.h>

namespace base {

inline int strcasecmp(const char* string1, const char* string2) {
  return ::strcasecmp(string1, string2);
}

inline int strncasecmp(const char* string1, const char* string2, size_t count) {
  return ::strncasecmp(string1, string2, count);
}

inline int vsnprintf(char* buffer, size_t size,
                     const char* format, va_list arguments) {
  return ::vsnprintf(buffer, size, format, arguments);
}

inline int vswprintf(wchar_t* buffer, size_t size,
                     const wchar_t* format, va_list arguments) {
  DCHECK(IsWprintfFormatPortable(format));
  return base::vswprintf(buffer, size, format, arguments);
}

}  // namespace base

#endif  // KEYCZAR_BASE_STRING_UTIL_POSIX_H_

