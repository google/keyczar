// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/string_escape.h>
#include <keyczar/base/string_util.h>

namespace keyczar {
namespace base {

TEST(StringEscapeTest, JavascriptDoubleQuote) {
  static const char* kToEscape          = "\b\001aZ\"\\wee";
  static const char* kEscaped           = "\\b\\x01aZ\\\"\\\\wee";
  static const char* kEscapedQuoted     = "\"\\b\\x01aZ\\\"\\\\wee\"";
  static const wchar_t* kUToEscape      = L"\b\x0001" L"a\x123fZ\"\\wee";
  static const char* kUEscaped          = "\\b\\x01a\\u123FZ\\\"\\\\wee";
  static const char* kUEscapedQuoted    = "\"\\b\\x01a\\u123FZ\\\"\\\\wee\"";

  std::string out;
  // Test escaping of 7bit ascii
  out = "testy: ";
  string_escape::JavascriptDoubleQuote(std::string(kToEscape), false, &out);
  ASSERT_EQ(std::string("testy: ") + kEscaped, out);

  out = "testy: ";
  string_escape::JavascriptDoubleQuote(std::string(kToEscape), true, &out);
  ASSERT_EQ(std::string("testy: ") + kEscapedQuoted, out);

  // Test null, non-printable, and non-7bit
  std::string str("TeSt");
  str.push_back(0);
  str.push_back(15);
  str.push_back(127);
  str.push_back(-16);
  str.push_back(-128);
  str.push_back('!');

  out = "testy: ";
  string_escape::JavascriptDoubleQuote(str, false, &out);
  ASSERT_EQ("testy: TeSt\\x00\\x0F\\x7F\xf0\x80!", out);

  // Test escape sequences
  out = "testy: ";
  string_escape::JavascriptDoubleQuote("a\b\f\n\r\t\v\1\\.\"z", false, &out);
  ASSERT_EQ("testy: a\\b\\f\\n\\r\\t\\v\\x01\\\\.\\\"z", out);
}

}  // namespace base
}  // namespace keyczar
