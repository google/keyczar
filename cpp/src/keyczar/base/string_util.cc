// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <keyczar/base/string_util.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>

#include <keyczar/base/logging.h>

namespace {

// Hack to convert any char-like type to its unsigned counterpart.
// For example, it will convert char, signed char and unsigned char to unsigned
// char.
template<typename T>
struct ToUnsigned {
  typedef T Unsigned;
};

template<>
struct ToUnsigned<char> {
  typedef unsigned char Unsigned;
};
template<>
struct ToUnsigned<signed char> {
  typedef unsigned char Unsigned;
};
template<>
struct ToUnsigned<short> {
  typedef unsigned short Unsigned;
};

template <typename CHAR>
size_t lcpyT(CHAR* dst, const CHAR* src, size_t dst_size) {
  for (size_t i = 0; i < dst_size; ++i) {
    if ((dst[i] = src[i]) == 0)  // We hit and copied the terminating NULL.
      return i;
  }

  // We were left off at dst_size.  We over copied 1 byte.  Null terminate.
  if (dst_size != 0)
    dst[dst_size - 1] = 0;

  // Count the rest of the |src|, and return it's length in characters.
  while (src[dst_size]) ++dst_size;
  return dst_size;
}

}  // namespace

namespace keyczar {
namespace base {

size_t strlcpy(char* dst, const char* src, size_t dst_size) {
  return lcpyT<char>(dst, src, dst_size);
}

}  // namespace base
}  // namespace keyczar

// Helper functions that determine whether the given character begins a
// UTF-8 sequence of bytes with the given length. A character satisfies
// "IsInUTF8Sequence" if it is anything but the first byte in a multi-byte
// character.
static inline bool IsBegin2ByteUTF8(int c) {
  return (c & 0xE0) == 0xC0;
}
static inline bool IsBegin3ByteUTF8(int c) {
  return (c & 0xF0) == 0xE0;
}
static inline bool IsBegin4ByteUTF8(int c) {
  return (c & 0xF8) == 0xF0;
}
static inline bool IsInUTF8Sequence(int c) {
  return (c & 0xC0) == 0x80;
}

// This function was copied from Mozilla, with modifications. The original code
// was 'IsUTF8' in xpcom/string/src/nsReadableUtils.cpp. The license block for
// this function is:
//   This function subject to the Mozilla Public License Version
//   1.1 (the "License"); you may not use this code except in compliance with
//   the License. You may obtain a copy of the License at
//   http://www.mozilla.org/MPL/
//
//   Software distributed under the License is distributed on an "AS IS" basis,
//   WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
//   for the specific language governing rights and limitations under the
//   License.
//
//   The Original Code is mozilla.org code.
//
//   The Initial Developer of the Original Code is
//   Netscape Communications Corporation.
//   Portions created by the Initial Developer are Copyright (C) 2000
//   the Initial Developer. All Rights Reserved.
//
//   Contributor(s):
//     Scott Collins <scc@mozilla.org> (original author)
//
// This is a template so that it can be run on wide and 8-bit strings. We want
// to run it on wide strings when we have input that we think may have
// originally been UTF-8, but has been converted to wide characters because
// that's what we (and Windows) use internally.
template<typename CHAR>
static bool IsStringUTF8T(const CHAR* str, int length) {
  bool overlong = false;
  bool surrogate = false;
  bool nonchar = false;

  // overlong byte upper bound
  typename ToUnsigned<CHAR>::Unsigned olupper = 0;

  // surrogate byte lower bound
  typename ToUnsigned<CHAR>::Unsigned slower = 0;

  // incremented when inside a multi-byte char to indicate how many bytes
  // are left in the sequence
  int positions_left = 0;

  for (int i = 0; i < length; i++) {
    // This whole function assume an unsigned value so force its conversion to
    // an unsigned value.
    typename ToUnsigned<CHAR>::Unsigned c = str[i];
    if (c < 0x80)
      continue;  // ASCII

    if (c <= 0xC1) {
      // [80-BF] where not expected, [C0-C1] for overlong
      return false;
    } else if (IsBegin2ByteUTF8(c)) {
      positions_left = 1;
    } else if (IsBegin3ByteUTF8(c)) {
      positions_left = 2;
      if (c == 0xE0) {
        // to exclude E0[80-9F][80-BF]
        overlong = true;
        olupper = 0x9F;
      } else if (c == 0xED) {
        // ED[A0-BF][80-BF]: surrogate codepoint
        surrogate = true;
        slower = 0xA0;
      } else if (c == 0xEF) {
        // EF BF [BE-BF] : non-character
        // TODO(jungshik): EF B7 [90-AF] should be checked as well.
        nonchar = true;
      }
    } else if (c <= 0xF4) {
      positions_left = 3;
      nonchar = true;
      if (c == 0xF0) {
        // to exclude F0[80-8F][80-BF]{2}
        overlong = true;
        olupper = 0x8F;
      } else if (c == 0xF4) {
        // to exclude F4[90-BF][80-BF]
        // actually not surrogates but codepoints beyond 0x10FFFF
        surrogate = true;
        slower = 0x90;
      }
    } else {
      return false;
    }

    // eat the rest of this multi-byte character
    while (positions_left) {
      positions_left--;
      i++;
      c = str[i];
      if (!c)
        return false;  // end of string but not end of character sequence

      // non-character : EF BF [BE-BF] or F[0-7] [89AB]F BF [BE-BF]
      if (nonchar && ((!positions_left && c < 0xBE) ||
                      (positions_left == 1 && c != 0xBF) ||
                      (positions_left == 2 && 0x0F != (0x0F & c) ))) {
        nonchar = false;
      }
      if (!IsInUTF8Sequence(c) || (overlong && c <= olupper) ||
          (surrogate && slower <= c) || (nonchar && !positions_left) ) {
        return false;
      }
      overlong = surrogate = false;
    }
  }
  return true;
}

bool IsStringUTF8(const std::string& str) {
  return IsStringUTF8T(str.data(), str.length());
}

// Overloaded wrappers around vsnprintf and vswprintf. The buf_size parameter
// is the size of the buffer. These return the number of characters in the
// formatted string excluding the NUL terminator. If the buffer is not
// large enough to accommodate the formatted string without truncation, they
// return the number of characters that would be in the fully-formatted string
// (vsnprintf, and vswprintf on Windows), or -1 (vswprintf on POSIX platforms).
inline int vsnprintfT(char* buffer,
                      size_t buf_size,
                      const char* format,
                      va_list argptr) {
  return base::vsnprintf(buffer, buf_size, format, argptr);
}

// Templatized backend for StringPrintF/StringAppendF. This does not finalize
// the va_list, the caller is expected to do that.
template <class char_type>
static void StringAppendVT(
    std::basic_string<char_type, std::char_traits<char_type> >* dst,
    const char_type* format,
    va_list ap) {

  // First try with a small fixed size buffer.
  // This buffer size should be kept in sync with StringUtilTest.GrowBoundary
  // and StringUtilTest.StringPrintfBounds.
  char_type stack_buf[1024];

  va_list backup_ap;
  base::xva_copy(backup_ap, ap);

#if !defined(OS_WIN)
  errno = 0;
#endif
  int result = vsnprintfT(stack_buf, arraysize(stack_buf), format, backup_ap);
  va_end(backup_ap);

  if (result >= 0 && result < static_cast<int>(arraysize(stack_buf))) {
    // It fit.
    dst->append(stack_buf, result);
    return;
  }

  // Repeatedly increase buffer size until it fits.
  int mem_length = arraysize(stack_buf);
  while (true) {
    if (result < 0) {
#if !defined(OS_WIN)
      // On Windows, vsnprintfT always returns the number of characters in a
      // fully-formatted string, so if we reach this point, something else is
      // wrong and no amount of buffer-doubling is going to fix it.
      if (errno != 0 && errno != EOVERFLOW)
#endif
      {
        // If an error other than overflow occurred, it's never going to work.
        DLOG(WARNING) << "Unable to printf the requested string due to error.";
        return;
      }
      // Try doubling the buffer size.
      mem_length *= 2;
    } else {
      // We need exactly "result + 1" characters.
      mem_length = result + 1;
    }

    if (mem_length > 32 * 1024 * 1024) {
      // That should be plenty, don't try anything larger.  This protects
      // against huge allocations when using vsnprintfT implementations that
      // return -1 for reasons other than overflow without setting errno.
      DLOG(WARNING) << "Unable to printf the requested string due to size.";
      return;
    }

    std::vector<char_type> mem_buf(mem_length);

    // Restore the va_list before we use it again.
    base::xva_copy(backup_ap, ap);

    result = vsnprintfT(&mem_buf[0], mem_length, format, ap);
    va_end(backup_ap);

    if ((result >= 0) && (result < mem_length)) {
      // It fit.
      dst->append(&mem_buf[0], result);
      return;
    }
  }
}

namespace {

template <typename STR, typename INT, typename UINT, bool NEG>
struct IntToStringT {
  // This is to avoid a compiler warning about unary minus on unsigned type.
  // For example, say you had the following code:
  //   template <typename INT>
  //   INT abs(INT value) { return value < 0 ? -value : value; }
  // Even though if INT is unsigned, it's impossible for value < 0, so the
  // unary minus will never be taken, the compiler will still generate a
  // warning.  We do a little specialization dance...
  template <typename INT2, typename UINT2, bool NEG2>
  struct ToUnsignedT { };

  template <typename INT2, typename UINT2>
  struct ToUnsignedT<INT2, UINT2, false> {
    static UINT2 ToUnsigned(INT2 value) {
      return static_cast<UINT2>(value);
    }
  };

  template <typename INT2, typename UINT2>
  struct ToUnsignedT<INT2, UINT2, true> {
    static UINT2 ToUnsigned(INT2 value) {
      return static_cast<UINT2>(value < 0 ? -value : value);
    }
  };

  static STR IntToString(INT value) {
    // log10(2) ~= 0.3 bytes needed per bit or per byte log10(2**8) ~= 2.4.
    // So round up to allocate 3 output characters per byte, plus 1 for '-'.
    const int kOutputBufSize = 3 * sizeof(INT) + 1;

    // Allocate the whole string right away, we will right back to front, and
    // then return the substr of what we ended up using.
    STR outbuf(kOutputBufSize, 0);

    bool is_neg = value < 0;
    // Even though is_neg will never be true when INT is parameterized as
    // unsigned, even the presence of the unary operation causes a warning.
    UINT res = ToUnsignedT<INT, UINT, NEG>::ToUnsigned(value);

    for (typename STR::iterator it = outbuf.end();;) {
      --it;
      DCHECK(it != outbuf.begin());
      *it = static_cast<typename STR::value_type>((res % 10) + '0');
      res /= 10;

      // We're done..
      if (res == 0) {
        if (is_neg) {
          --it;
          DCHECK(it != outbuf.begin());
          *it = static_cast<typename STR::value_type>('-');
        }
        return STR(it, outbuf.end());
      }
    }
    NOTREACHED();
    return STR();
  }
};

}  // namespace

std::string IntToString(int value) {
  return IntToStringT<std::string, int, unsigned int, true>::
      IntToString(value);
}
std::string UintToString(unsigned int value) {
  return IntToStringT<std::string, unsigned int, unsigned int, false>::
      IntToString(value);
}
std::string Int64ToString(int64 value) {
  return IntToStringT<std::string, int64, uint64, true>::
      IntToString(value);
}
std::string Uint64ToString(uint64 value) {
  return IntToStringT<std::string, uint64, uint64, false>::
      IntToString(value);
}

void StringAppendV(std::string* dst, const char* format, va_list ap) {
  StringAppendVT<char>(dst, format, ap);
}

std::string StringPrintf(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  std::string result;
  StringAppendV(&result, format, ap);
  va_end(ap);
  return result;
}

const std::string& SStringPrintf(std::string* dst, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  dst->clear();
  StringAppendV(dst, format, ap);
  va_end(ap);
  return *dst;
}

void StringAppendF(std::string* dst, const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  StringAppendV(dst, format, ap);
  va_end(ap);
}

// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// http://code.google.com/p/protobuf/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Copied from src/google/protobuf/stubs/strutil.cc

// ----------------------------------------------------------------------
// strto32_adaptor()
// strtou32_adaptor()
//    Implementation of strto[u]l replacements that have identical
//    overflow and underflow characteristics for both ILP-32 and LP-64
//    platforms, including errno preservation in error-free calls.
// ----------------------------------------------------------------------

int32 strto32_adaptor(const char *nptr, char **endptr, int base) {
  const int saved_errno = errno;
  errno = 0;
  const long result = strtol(nptr, endptr, base);
  if (errno == ERANGE && result == LONG_MIN) {
    return kint32min;
  } else if (errno == ERANGE && result == LONG_MAX) {
    return kint32max;
  } else if (errno == 0 && result < kint32min) {
    errno = ERANGE;
    return kint32min;
  } else if (errno == 0 && result > kint32max) {
    errno = ERANGE;
    return kint32max;
  }
  if (errno == 0)
    errno = saved_errno;
  return static_cast<int32>(result);
}

uint32 strtou32_adaptor(const char *nptr, char **endptr, int base) {
  const int saved_errno = errno;
  errno = 0;
  const unsigned long result = strtoul(nptr, endptr, base);
  if (errno == ERANGE && result == ULONG_MAX) {
    return kuint32max;
  } else if (errno == 0 && result > kuint32max) {
    errno = ERANGE;
    return kuint32max;
  }
  if (errno == 0)
    errno = saved_errno;
  return static_cast<uint32>(result);
}
