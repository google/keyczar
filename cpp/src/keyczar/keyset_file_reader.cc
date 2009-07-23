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
#include <keyczar/keyset_file_reader.h>

#include <keyczar/base/file_util.h>
#include <keyczar/base/json_value_serializer.h>
#include <keyczar/base/string_util.h>

namespace {

Value* ReadJSONFile(const FilePath& file) {
  JSONFileValueSerializer json_serializer(file);
  std::string error;
  scoped_ptr<Value> root(json_serializer.Deserialize(&error));
  if (root.get() == NULL) {
    LOG(ERROR) << error;
     return NULL;
  }
  return root.release();
}

}  // namespace

namespace keyczar {

KeysetFileReader::KeysetFileReader(const std::string& dirname)
    : dirname_(dirname), metadata_basename_("meta") {
  CHECK(file_util::PathExists(dirname_));
}

KeysetFileReader::KeysetFileReader(const FilePath& dirname)
    : dirname_(dirname), metadata_basename_("meta") {
  CHECK(file_util::PathExists(dirname_));
}

Value* KeysetFileReader::ReadMetadata() const {
  FilePath metadata_file = dirname_.Append(metadata_basename_);
  if (!file_util::PathExists(metadata_file))
    return NULL;
  return ReadJSONFile(metadata_file);
}

Value* KeysetFileReader::ReadKey(int version) const {
  FilePath key_file = dirname_.Append(FilePath(IntToString(version)));
  if (!file_util::PathExists(key_file))
    return NULL;
  return ReadJSONFile(key_file);
}

}  // namespace keyczar
