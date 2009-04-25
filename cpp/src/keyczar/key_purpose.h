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
#ifndef KEYCZAR_KEY_PURPOSE_H_
#define KEYCZAR_KEY_PURPOSE_H_

#include <string>

#include "base/basictypes.h"

namespace keyczar {

// Encodes the different possible purposes for which a key can be used:
// - Decrypt and Encrypt
// - Encrypt (only)
// - Sign and Verify
// - Verify (only)
class KeyPurpose {
 public:
  enum Type {
    DECRYPT_AND_ENCRYPT = 0,
    ENCRYPT,
    SIGN_AND_VERIFY,
    VERIFY
  };

  explicit KeyPurpose(Type type) : type_(type) {}

  // Creates KeyPurpose instance from string |name|. The caller takes
  // ownership of the result.
  static KeyPurpose* Create(const std::string& name);

  Type type() const { return type_; }

  bool GetName(std::string* name) const;

 private:
  Type type_;

  DISALLOW_COPY_AND_ASSIGN(KeyPurpose);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEY_PURPOSE_H_
