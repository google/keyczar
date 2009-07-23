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
#include <keyczar/keyset_writer.h>

#include <keyczar/base/scoped_ptr.h>

namespace keyczar {

void KeysetWriter::OnUpdatedKeysetMetadata(const KeysetMetadata& key_metadata) {
  scoped_ptr<Value> metadata_value(key_metadata.GetValue(false));
  WriteMetadata(metadata_value.get());
}

void KeysetWriter::OnNewKey(const Key& key, int version_number) {
  scoped_ptr<Value> key_value(key.GetValue());
  WriteKey(key_value.get(), version_number);
}

void KeysetWriter::OnRevokedKey(int version_number) {
  // By default, does nothing.
}

}  // namespace keyczar
