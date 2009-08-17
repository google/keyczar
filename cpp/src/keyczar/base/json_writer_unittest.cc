// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/json_writer.h>
#include <keyczar/base/values.h>

namespace keyczar {
namespace base {

TEST(JSONWriterTest, Writing) {
  // Test null
  Value* root = Value::CreateNullValue();
  std::string output_js;
  JSONWriter::Write(root, false, &output_js);
  ASSERT_EQ("null", output_js);
  delete root;

  // Test empty dict
  root = new DictionaryValue;
  JSONWriter::Write(root, false, &output_js);
  ASSERT_EQ("{}", output_js);
  delete root;

  // Test empty list
  root = new ListValue;
  JSONWriter::Write(root, false, &output_js);
  ASSERT_EQ("[]", output_js);
  delete root;

  // Writer unittests like empty list/dict nesting,
  // list list nesting, etc.
  DictionaryValue root_dict;
  ListValue* list = new ListValue;
  root_dict.Set("list", list);
  DictionaryValue* inner_dict = new DictionaryValue;
  list->Append(inner_dict);
  inner_dict->SetInteger("inner int", 10);
  ListValue* inner_list = new ListValue;
  list->Append(inner_list);
  list->Append(Value::CreateBooleanValue(true));

  JSONWriter::Write(&root_dict, false, &output_js);
  ASSERT_EQ("{\"list\":[{\"inner int\":10},[],true]}", output_js);
  JSONWriter::Write(&root_dict, true, &output_js);
  ASSERT_EQ("{\r\n"
            "   \"list\": [ {\r\n"
            "      \"inner int\": 10\r\n"
            "   }, [  ], true ]\r\n"
            "}\r\n",
            output_js);
}

}  // namespace base
}  // namespace keyczar
