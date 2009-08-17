// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copied from src/chrome/common/json_value_serializer_unittest.cc

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <keyczar/base/basictypes.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_value_serializer.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/string_util.h>
#include <keyczar/base/values.h>
#include <keyczar/base_test/path_service.h>

#include <testing/gtest/include/gtest/gtest.h>
#include <testing/platform_test.h>

namespace keyczar {
namespace base {

TEST(JSONValueSerializerTest, Roundtrip) {
  const std::string original_serialization =
    "{\"bool\":true,\"int\":42,\"list\":[1,2],\"null\":null}";
  JSONStringValueSerializer serializer(original_serialization);
  scoped_ptr<Value> root(serializer.Deserialize(NULL));
  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_DICTIONARY));

  DictionaryValue* root_dict = static_cast<DictionaryValue*>(root.get());

  Value* null_value = NULL;
  ASSERT_TRUE(root_dict->Get("null", &null_value));
  ASSERT_TRUE(null_value);
  ASSERT_TRUE(null_value->IsType(Value::TYPE_NULL));

  bool bool_value = false;
  ASSERT_TRUE(root_dict->GetBoolean("bool", &bool_value));
  ASSERT_TRUE(bool_value);

  int int_value = 0;
  ASSERT_TRUE(root_dict->GetInteger("int", &int_value));
  ASSERT_EQ(42, int_value);

  // We shouldn't be able to write using this serializer, since it was
  // initialized with a const string.
  ASSERT_FALSE(serializer.Serialize(*root_dict));

  std::string test_serialization = "";
  JSONStringValueSerializer mutable_serializer(&test_serialization);
  ASSERT_TRUE(mutable_serializer.Serialize(*root_dict));
  ASSERT_EQ(original_serialization, test_serialization);

  mutable_serializer.set_pretty_print(true);
  ASSERT_TRUE(mutable_serializer.Serialize(*root_dict));
  const std::string pretty_serialization =
    "{\r\n"
    "   \"bool\": true,\r\n"
    "   \"int\": 42,\r\n"
    "   \"list\": [ 1, 2 ],\r\n"
    "   \"null\": null\r\n"
    "}\r\n";
  ASSERT_EQ(pretty_serialization, test_serialization);
}

TEST(JSONValueSerializerTest, AllowTrailingComma) {
  scoped_ptr<Value> root;
  scoped_ptr<Value> root_expected;
  std::string test_with_commas("{\"key\": [true,],}");
  std::string test_no_commas("{\"key\": [true]}");

  JSONStringValueSerializer serializer(test_with_commas);
  serializer.set_allow_trailing_comma(true);
  JSONStringValueSerializer serializer_expected(test_no_commas);
  root.reset(serializer.Deserialize(NULL));
  ASSERT_TRUE(root.get());
  root_expected.reset(serializer_expected.Deserialize(NULL));
  ASSERT_TRUE(root_expected.get());
  ASSERT_TRUE(root->Equals(root_expected.get()));
}

namespace {

void ValidateJsonList(const std::string& json) {
  scoped_ptr<Value> root(JSONReader::Read(json, false));
  ASSERT_TRUE(root.get() && root->IsType(Value::TYPE_LIST));
  ListValue* list = static_cast<ListValue*>(root.get());
  ASSERT_EQ(1U, list->GetSize());
  Value* elt = NULL;
  ASSERT_TRUE(list->Get(0, &elt));
  int value = 0;
  ASSERT_TRUE(elt && elt->GetAsInteger(&value));
  ASSERT_EQ(1, value);
}

}  // namespace

TEST(JSONValueSerializerTest, JSONReaderComments) {
  ValidateJsonList("[ // 2, 3, ignore me ] \n1 ]");
  ValidateJsonList("[ /* 2, \n3, ignore me ]*/ \n1 ]");
  ValidateJsonList("//header\n[ // 2, \n// 3, \n1 ]// footer");
  ValidateJsonList("/*\n[ // 2, \n// 3, \n1 ]*/[1]");
  ValidateJsonList("[ 1 /* one */ ] /* end */");
  ValidateJsonList("[ 1 //// ,2\r\n ]");

  scoped_ptr<Value> root;

  // It's ok to have a comment in a string.
  root.reset(JSONReader::Read("[\"// ok\\n /* foo */ \"]", false));
  ASSERT_TRUE(root.get() && root->IsType(Value::TYPE_LIST));
  ListValue* list = static_cast<ListValue*>(root.get());
  ASSERT_EQ(1U, list->GetSize());
  Value* elt = NULL;
  ASSERT_TRUE(list->Get(0, &elt));

  // You can't nest comments.
  root.reset(JSONReader::Read("/* /* inner */ outer */ [ 1 ]", false));
  ASSERT_FALSE(root.get());

  // Not a open comment token.
  root.reset(JSONReader::Read("/ * * / [1]", false));
  ASSERT_FALSE(root.get());
}

class JSONFileValueSerializerTest : public PlatformTest {
 protected:
  virtual void SetUp() {
    PlatformTest::SetUp();
    // Name a subdirectory of the temp directory.
    ASSERT_TRUE(base_test::PathService::Get(base_test::DIR_TEMP,
                                            &test_dir_));
    test_dir_ = test_dir_.Append("JSONFileValueSerializerTest");

    // Create a fresh, empty copy of this directory.
    Delete(test_dir_, true);
    CreateDirectory(test_dir_);
  }
  virtual void TearDown() {
    PlatformTest::TearDown();
    // Clean up test directory
    ASSERT_TRUE(Delete(test_dir_, false));
    ASSERT_FALSE(PathExists(test_dir_));
  }

  // the path to temporary directory used to contain the test operations
  FilePath test_dir_;
};

TEST_F(JSONFileValueSerializerTest, Roundtrip) {
  FilePath original_file_path;
  ASSERT_TRUE(
    base_test::PathService::Get(base_test::DIR_SOURCE_ROOT,
                                &original_file_path));
  original_file_path = original_file_path.Append("keyczar");
  original_file_path = original_file_path.Append("base");
  original_file_path = original_file_path.Append("data");
  original_file_path =
      original_file_path.Append("json_value_serializer_unittest");
  original_file_path = original_file_path.Append("serializer_test.js");

  ASSERT_TRUE(PathExists(original_file_path));

  JSONFileValueSerializer deserializer(original_file_path);
  scoped_ptr<Value> root;
  root.reset(deserializer.Deserialize(NULL));

  ASSERT_TRUE(root.get());
  ASSERT_TRUE(root->IsType(Value::TYPE_DICTIONARY));

  DictionaryValue* root_dict = static_cast<DictionaryValue*>(root.get());

  Value* null_value = NULL;
  ASSERT_TRUE(root_dict->Get("null", &null_value));
  ASSERT_TRUE(null_value);
  ASSERT_TRUE(null_value->IsType(Value::TYPE_NULL));

  bool bool_value = false;
  ASSERT_TRUE(root_dict->GetBoolean("bool", &bool_value));
  ASSERT_TRUE(bool_value);

  int int_value = 0;
  ASSERT_TRUE(root_dict->GetInteger("int", &int_value));
  ASSERT_EQ(42, int_value);

  // Now try writing.
  FilePath written_file_path = test_dir_;
  written_file_path = written_file_path.Append("test_output.js");

  ASSERT_FALSE(PathExists(written_file_path));
  JSONFileValueSerializer serializer(written_file_path);
  ASSERT_TRUE(serializer.Serialize(*root));
  ASSERT_TRUE(PathExists(written_file_path));

  // Now compare file contents.
  std::string fa, fb;
  ASSERT_TRUE(ReadFileToString(original_file_path, &fa));
  ASSERT_TRUE(ReadFileToString(written_file_path, &fb));
  EXPECT_EQ(fa, fb);
  EXPECT_TRUE(Delete(written_file_path, false));
}

TEST_F(JSONFileValueSerializerTest, RoundtripNested) {
  FilePath original_file_path;
  ASSERT_TRUE(
    base_test::PathService::Get(base_test::DIR_SOURCE_ROOT,
                                &original_file_path));
  original_file_path = original_file_path.Append("keyczar");
  original_file_path = original_file_path.Append("base");
  original_file_path = original_file_path.Append("data");
  original_file_path =
      original_file_path.Append("json_value_serializer_unittest");
  original_file_path = original_file_path.Append("serializer_nested_test.js");
  ASSERT_TRUE(PathExists(original_file_path));

  JSONFileValueSerializer deserializer(original_file_path);
  scoped_ptr<Value> root;
  root.reset(deserializer.Deserialize(NULL));
  ASSERT_TRUE(root.get());

  // Now try writing.
  FilePath written_file_path = test_dir_;
  written_file_path = written_file_path.Append("test_output.js");

  ASSERT_FALSE(PathExists(written_file_path));
  JSONFileValueSerializer serializer(written_file_path);
  ASSERT_TRUE(serializer.Serialize(*root));
  ASSERT_TRUE(PathExists(written_file_path));

  // Now compare file contents.
  std::string fa, fb;
  ASSERT_TRUE(ReadFileToString(original_file_path, &fa));
  ASSERT_TRUE(ReadFileToString(written_file_path, &fb));
  EXPECT_EQ(fa, fb);
  EXPECT_TRUE(Delete(written_file_path, false));
}

TEST_F(JSONFileValueSerializerTest, NoWhitespace) {
  FilePath source_file_path;
  ASSERT_TRUE(base_test::PathService::Get(base_test::DIR_SOURCE_ROOT,
                                          &source_file_path));
  source_file_path = source_file_path.Append("keyczar");
  source_file_path = source_file_path.Append("base");
  source_file_path = source_file_path.Append("data");
  source_file_path = source_file_path.Append("json_value_serializer_unittest");
  source_file_path = source_file_path.Append("serializer_test_nowhitespace.js");
  ASSERT_TRUE(PathExists(source_file_path));

  JSONFileValueSerializer serializer(source_file_path);
  scoped_ptr<Value> root;
  root.reset(serializer.Deserialize(NULL));
  ASSERT_TRUE(root.get());
}

}  // namespace base
}  // namespace keyczar
