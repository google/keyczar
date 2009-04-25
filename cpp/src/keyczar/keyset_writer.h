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
#ifndef KEYCZAR_KEYSET_WRITER_H_
#define KEYCZAR_KEYSET_WRITER_H_

#include "base/basictypes.h"
#include "base/values.h"

namespace keyczar {

// Keyser writer interface.
class KeysetWriter {
 public:
  KeysetWriter() {}
  virtual ~KeysetWriter() {}

  // Abstract method for writing |metadata|.
  virtual bool WriteMetadata(const Value* metadata) const = 0;

  // Abstract method for writing |key| of number |version|.
  virtual bool WriteKey(const Value* key, int version) const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(KeysetWriter);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_WRITER_H_
