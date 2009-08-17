// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file defines utility functions for escaping strings.

// This source code was copied from Chromium and was modified, any
// encountered errors are probably due to these modifications.

#ifndef KEYCZAR_BASE_STRING_ESCAPE_H_
#define KEYCZAR_BASE_STRING_ESCAPE_H_

#include <string>

namespace keyczar {
namespace base {
namespace string_escape {

// Similar to the wide version, but for narrow strings.  It will not use
// \uXXXX unicode escape sequences.  It will pass non-7bit characters directly
// into the string unencoded, allowing the browser to interpret the encoding.
// The outputted literal, when interpreted by the browser, could result in a
// javascript string of a different length than the input |str|.
void JavascriptDoubleQuote(const std::string& str,
                           bool put_in_quotes,
                           std::string* dst);

}  // namespace string_escape
}  // namespace base
}  // namespace keyczar

#endif  // KEYCZAR_BASE_STRING_ESCAPE_H_
