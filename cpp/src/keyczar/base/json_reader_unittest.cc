// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/build_config.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>

namespace keyczar {
namespace base {

TEST(JSONReaderTest, Reading) {
  // some whitespace checking
  scoped_ptr<Value> root;
  root.reset(JSONReader().JsonToValue("   null   ", false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_NULL));

  // Invalid JSON string
  root.reset(JSONReader().JsonToValue("nu", false, false));
  ASSERT_FALSE(root.get());

  // Simple bool
  root.reset(JSONReader().JsonToValue("true  ", false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_BOOLEAN));

  // Test number formats
  root.reset(JSONReader().JsonToValue("43", false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_INTEGER));
  int int_val = 0;
  ASSERT_TRUE(root->GetAsInteger(&int_val));
  ASSERT_EQ(43, int_val);

  // According to RFC4627, oct, hex, and leading zeros are invalid JSON.
  root.reset(JSONReader().JsonToValue("043", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("0x43", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("00", false, false));
  ASSERT_FALSE(root.get());

  // Test 0 (which needs to be special cased because of the leading zero
  // clause).
  root.reset(JSONReader().JsonToValue("0", false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_INTEGER));
  int_val = 1;
  ASSERT_TRUE(root->GetAsInteger(&int_val));
  ASSERT_EQ(0, int_val);

  // Fractional parts must have a digit before and after the decimal point.
  root.reset(JSONReader().JsonToValue("1.", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue(".1", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("1.e10", false, false));
  ASSERT_FALSE(root.get());

  // Exponent must have a digit following the 'e'.
  root.reset(JSONReader().JsonToValue("1e", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("1E", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("1e1.", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("1e1.0", false, false));
  ASSERT_FALSE(root.get());

  // INF/-INF/NaN are not valid
  /*
  root.reset(JSONReader().JsonToValue("1e1000", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("-1e1000", false, false));
  ASSERT_FALSE(root.get());
  */
  root.reset(JSONReader().JsonToValue("NaN", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("nan", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("inf", false, false));
  ASSERT_FALSE(root.get());

  // Invalid number formats
  root.reset(JSONReader().JsonToValue("4.3.1", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("4e3.1", false, false));
  ASSERT_FALSE(root.get());

  // Test string parser
  root.reset(JSONReader().JsonToValue("\"hello world\"", false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_STRING));

  // Empty string
  root.reset(JSONReader().JsonToValue("\"\"", false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_STRING));

  // Test basic string escapes
  root.reset(JSONReader().JsonToValue("\" \\\"\\\\\\/\\b\\f\\n\\r\\t\\v\"",
                                      false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_STRING));

  // Test invalid strings
  root.reset(JSONReader().JsonToValue("\"no closing quote", false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("\"\\z invalid escape char\"", false,
                                      false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("\"\\xAQ invalid hex code\"", false,
                                      false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("not enough hex chars\\x1\"", false,
                                      false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("\"not enough escape chars\\u123\"",
                                      false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("\"extra backslash at end of input\\\"",
                                      false, false));
  ASSERT_FALSE(root.get());

  // Basic array
  root.reset(JSONReader::Read("[true, false, null]", false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_LIST));
  ListValue* list = static_cast<ListValue*>(root.get());
  ASSERT_EQ(3U, list->GetSize());

  // Test with trailing comma.  Should be parsed the same as above.
  scoped_ptr<Value> root2;
  root2.reset(JSONReader::Read("[true, false, null, ]", true));
  EXPECT_TRUE(root->Equals(root2.get()));

  // Empty array
  root.reset(JSONReader::Read("[]", false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_LIST));
  list = static_cast<ListValue*>(root.get());
  ASSERT_EQ(0U, list->GetSize());

  // Nested arrays
  root.reset(JSONReader::Read("[[true], [], [false, [], [null]], null]",
                              false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_LIST));
  list = static_cast<ListValue*>(root.get());
  ASSERT_EQ(4U, list->GetSize());

  // Lots of trailing commas.
  root2.reset(JSONReader::Read("[[true], [], [false, [], [null, ]  , ], null,]",
                               true));
  EXPECT_TRUE(root->Equals(root2.get()));

  // Invalid, missing close brace.
  root.reset(JSONReader::Read("[[true], [], [false, [], [null]], null", false));
  ASSERT_FALSE(root.get());

  // Invalid, too many commas
  root.reset(JSONReader::Read("[true,, null]", false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("[true,, null]", true));
  ASSERT_FALSE(root.get());

  // Invalid, no commas
  root.reset(JSONReader::Read("[true null]", false));
  ASSERT_FALSE(root.get());

  // Invalid, trailing comma
  root.reset(JSONReader::Read("[true,]", false));
  ASSERT_FALSE(root.get());

  // Valid if we set |allow_trailing_comma| to true.
  root.reset(JSONReader::Read("[true,]", true));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_LIST));
  list = static_cast<ListValue*>(root.get());
  EXPECT_EQ(1U, list->GetSize());
  Value* tmp_value = NULL;
  ASSERT_TRUE(list->Get(0, &tmp_value));
  EXPECT_TRUE(tmp_value->IsType(Value::TYPE_BOOLEAN));
  bool bool_value = false;
  ASSERT_TRUE(tmp_value->GetAsBoolean(&bool_value));
  EXPECT_TRUE(bool_value);

  // Don't allow empty elements, even if |allow_trailing_comma| is
  // true.
  root.reset(JSONReader::Read("[,]", true));
  EXPECT_FALSE(root.get());
  root.reset(JSONReader::Read("[true,,]", true));
  EXPECT_FALSE(root.get());
  root.reset(JSONReader::Read("[,true,]", true));
  EXPECT_FALSE(root.get());
  root.reset(JSONReader::Read("[true,,false]", true));
  EXPECT_FALSE(root.get());

  // Test objects
  root.reset(JSONReader::Read("{}", false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_DICTIONARY));

  root.reset(JSONReader::Read(
    "{\"null\":null , \"\\x53\" : \"str\" }",
    false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_DICTIONARY));
  DictionaryValue* dict_val = static_cast<DictionaryValue*>(root.get());
  Value* null_val = NULL;
  ASSERT_TRUE(dict_val->Get("null", &null_val));
  ASSERT_TRUE(null_val->IsType(Value::TYPE_NULL));

  root2.reset(JSONReader::Read(
    "{\"null\":null , \"\\x53\" : \"str\", }", true));
  EXPECT_TRUE(root->Equals(root2.get()));

  // Test nesting
  root.reset(JSONReader::Read(
    "{\"inner\":{\"array\":[true]},\"false\":false,\"d\":{}}", false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_DICTIONARY));
  dict_val = static_cast<DictionaryValue*>(root.get());
  DictionaryValue* inner_dict = NULL;
  ASSERT_TRUE(dict_val->GetDictionary("inner", &inner_dict));
  ListValue* inner_array = NULL;
  ASSERT_TRUE(inner_dict->GetList("array", &inner_array));
  ASSERT_EQ(1U, inner_array->GetSize());
  bool_value = true;
  ASSERT_TRUE(dict_val->GetBoolean("false", &bool_value));
  ASSERT_FALSE(bool_value);
  inner_dict = NULL;
  ASSERT_TRUE(dict_val->GetDictionary("d", &inner_dict));

  root2.reset(JSONReader::Read(
    "{\"inner\": {\"array\":[true] , },\"false\":false,\"d\":{},}", true));
  EXPECT_TRUE(root->Equals(root2.get()));

  // Invalid, no closing brace
  root.reset(JSONReader::Read("{\"a\": true", false));
  ASSERT_FALSE(root.get());

  // Invalid, keys must be quoted
  root.reset(JSONReader::Read("{foo:true}", false));
  ASSERT_FALSE(root.get());

  // Invalid, trailing comma
  root.reset(JSONReader::Read("{\"a\":true,}", false));
  ASSERT_FALSE(root.get());

  // Invalid, too many commas
  root.reset(JSONReader::Read("{\"a\":true,,\"b\":false}", false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("{\"a\":true,,\"b\":false}", true));
  ASSERT_FALSE(root.get());

  // Invalid, no separator
  root.reset(JSONReader::Read("{\"a\" \"b\"}", false));
  ASSERT_FALSE(root.get());

  // Invalid, lone comma.
  root.reset(JSONReader::Read("{,}", false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("{,}", true));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("{\"a\":true,,}", true));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("{,\"a\":true}", true));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("{\"a\":true,,\"b\":false}", true));
  ASSERT_FALSE(root.get());

  // Test stack overflow
  std::string evil(1000000, '[');
  evil.append(std::string(1000000, ']'));
  root.reset(JSONReader::Read(evil, false));
  ASSERT_FALSE(root.get());

  // A few thousand adjacent lists is fine.
  std::string not_evil("[");
  not_evil.reserve(15010);
  for (int i = 0; i < 5000; ++i) {
    not_evil.append("[],");
  }
  not_evil.append("[]]");
  root.reset(JSONReader::Read(not_evil, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_LIST));
  list = static_cast<ListValue*>(root.get());
  ASSERT_EQ(5001U, list->GetSize());

  // Test utf8 encoded input
  root.reset(JSONReader().JsonToValue("\"\xe7\xbd\x91\xe9\xa1\xb5\"",
                                      false, false));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_STRING));

  // Test invalid utf8 encoded input
  root.reset(JSONReader().JsonToValue("\"345\xb0\xa1\xb0\xa2\"",
                                      false, false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader().JsonToValue("\"123\xc0\x81\"",
                                      false, false));
  ASSERT_FALSE(root.get());

  // Test invalid root objects.
  root.reset(JSONReader::Read("null", false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("true", false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("10", false));
  ASSERT_FALSE(root.get());
  root.reset(JSONReader::Read("\"root\"", false));
  ASSERT_FALSE(root.get());
}

}  // namespace base
}  // namespace keyczar
