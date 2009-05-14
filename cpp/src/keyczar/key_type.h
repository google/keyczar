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
#ifndef KEYCZAR_KEY_TYPE_H_
#define KEYCZAR_KEY_TYPE_H_

#include <string>
#include <vector>

#include "base/basictypes.h"

namespace keyczar {

class KeyType {
 public:
  enum Type {
    AES = 0,
#ifdef COMPAT_KEYCZAR_05B
    HMAC_SHA1,
#else
    HMAC,
#endif
    DSA_PRIV,
    DSA_PUB,
    ECDSA_PRIV,
    ECDSA_PUB,
    RSA_PRIV,
    RSA_PUB
  };
  KeyType(Type type, const std::vector<int>& valid_sizes, int default_size);

  // Creates KeyStatus instance from string |name|. The caller takes
  // ownership of the result.
  static KeyType* Create(const std::string& name);

  Type type() const { return type_; }

  bool GetName(std::string* name) const;

  int default_size() const { return default_size_; }

  bool IsValidSize(int size) const;

  std::vector<int> sizes() { return sizes_; }

 private:
  Type type_;
  std::vector<int> sizes_;
  int default_size_;

  DISALLOW_COPY_AND_ASSIGN(KeyType);
};

bool IsValidSize(const std::string& key_type_name, int size);

}  // namespace keyczar

#endif  // KEYCZAR_KEY_TYPE_H_
