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
#ifndef KEYCZAR_CIPHER_MODE_H_
#define KEYCZAR_CIPHER_MODE_H_

#include <string>

#include "base/basictypes.h"

namespace keyczar {

class CipherMode {
 public:
  enum Type {
    CBC = 0,
    CTR,
    ECB,
    DET_CBC
  };

  CipherMode(Type type, bool use_iv) : type_(type), use_iv_(use_iv) {}

  // Creates KeyPurpose instance from string |name|. The caller takes
  // ownership of the result.
  static CipherMode* Create(const std::string& name);

  Type type() const { return type_; }

  bool GetName(std::string* name) const;

  bool use_iv() const { return use_iv_; }

  int GetOutputSize(int block_size, int input_length) const;

 private:
  Type type_;
  bool use_iv_;

  DISALLOW_COPY_AND_ASSIGN(CipherMode);
};

}  // namespace keyczar

#endif  // KEYCZAR_CIPHER_MODE_H_
