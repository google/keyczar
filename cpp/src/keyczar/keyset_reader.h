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
#ifndef KEYCZAR_KEYSET_READER_H_
#define KEYCZAR_KEYSET_READER_H_

#include "base/basictypes.h"
#include "base/values.h"

namespace keyczar {

// Keyset reader interface.
class KeysetReader {
 public:
  KeysetReader() {}
  virtual ~KeysetReader() {}

  // Reads metadata and returns a Value object. The caller takes
  // ownership of the returned value.
  virtual Value* ReadMetadata() const = 0;

  // Reads the key |version| and resturns a Value object. The caller
  // takes ownership of the returned value.
  virtual Value* ReadKey(int version) const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(KeysetReader);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_READER_H_
