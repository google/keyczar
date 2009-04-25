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
#ifndef KEYCZAR_OPENSSL_UTIL_H_
#define KEYCZAR_OPENSSL_UTIL_H_

#include <openssl/err.h>

#include "base/logging.h"

namespace keyczar {

namespace openssl {

template <typename Type, void (*Destroyer)(Type*)>
struct OSSLDestroyer {
  void operator()(Type* ptr) const {
    if (ptr)
      Destroyer(ptr);
  }
};

void PrintOSSLErrors();

}  // namespace openssl

}  // namespace keyczar

#endif  // KEYCZAR_OPENSSL_UTIL_H_
