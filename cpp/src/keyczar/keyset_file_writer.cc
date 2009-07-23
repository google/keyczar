// Copyright 2009 Sebastien Martini (seb@dbzteam.org)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <keyczar/keyset_file_writer.h>

#include <keyczar/base/file_util.h>
#include <keyczar/base/json_value_serializer.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/string_util.h>

namespace {

bool WriteJSONFile(const FilePath& file, const Value* root) {
  if (!root)
    return false;
  JSONFileValueSerializer json_serializer(file);
  return json_serializer.Serialize(*root);
}

}  // namespace

namespace keyczar {

KeysetFileWriter::KeysetFileWriter(const std::string& dirname)
    : dirname_(dirname), metadata_basename_("meta") {
  CHECK(file_util::PathExists(dirname_));
}

KeysetFileWriter::KeysetFileWriter(const FilePath& dirname)
    : dirname_(dirname), metadata_basename_("meta") {
  CHECK(file_util::PathExists(dirname_));
}

bool KeysetFileWriter::WriteMetadata(const Value* metadata) const {
  if (!file_util::PathExists(dirname_))
    return false;
  FilePath metadata_file = dirname_.Append(metadata_basename_);
  return WriteJSONFile(metadata_file, metadata);
}

bool KeysetFileWriter::WriteKey(const Value* key, int version) const {
  if (!file_util::PathExists(dirname_))
    return false;
  FilePath key_file = dirname_.Append(FilePath(IntToString(version)));
  return WriteJSONFile(key_file, key);
}

}  // namespace keyczar
