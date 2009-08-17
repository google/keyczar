// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copied from src/chrome/common/json_value_serializer.cc

// This source code was copied from Chromium and has been modified to fit
// with Keyczar, any encountered errors are probably due to these
// modifications.

#include <keyczar/base/json_value_serializer.h>

#include <keyczar/base/file_util.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/stl_util-inl.h>

namespace keyczar {
namespace base {

JSONStringValueSerializer::~JSONStringValueSerializer() {}

bool JSONStringValueSerializer::Serialize(const Value& root) {
  if (!json_string_ || initialized_with_const_string_)
    return false;

  JSONWriter::Write(&root, pretty_print_, json_string_);

  return true;
}

Value* JSONStringValueSerializer::Deserialize(std::string* error_message) {
  if (!json_string_)
    return NULL;

  return JSONReader::ReadAndReturnError(*json_string_, allow_trailing_comma_,
                                        error_message);
}

/******* File Serializer *******/

bool JSONFileValueSerializer::Serialize(const Value& root) {
  ScopedSafeString json_string(new std::string());
  JSONStringValueSerializer serializer(json_string.get());
  serializer.set_pretty_print(true);
  if (!serializer.Serialize(root))
    return false;
  return WriteStringToFile(json_file_path_, *json_string);
}

Value* JSONFileValueSerializer::Deserialize(std::string* error_message) {
  ScopedSafeString json_string(new std::string());
  if (!ReadFileToString(json_file_path_, json_string.get()))
    return NULL;
  JSONStringValueSerializer serializer(json_string.get());
  return serializer.Deserialize(error_message);
}

}  // namespace base
}  // namespace keyczar
