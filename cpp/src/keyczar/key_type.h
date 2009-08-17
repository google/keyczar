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

#include <keyczar/base/basictypes.h>

namespace keyczar {

class KeyType {
 public:
  enum Type {
    UNDEF,
    AES,
#ifdef COMPAT_KEYCZAR_06B
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

  static Type GetTypeFromName(const std::string& name);

  static std::string GetNameFromType(Type type);

  static int DefaultCipherSize(Type type);

  static bool IsValidCipherSize(Type type, int size);

  static std::vector<int> CipherSizes(Type type);

 private:
  KeyType();

  DISALLOW_COPY_AND_ASSIGN(KeyType);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEY_TYPE_H_
