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

#include <keyczar/base/basictypes.h>

namespace keyczar {

class CipherMode {
 public:
  enum Type {
    UNDEF,
    CBC,
    CTR,
    ECB,
    DET_CBC
  };

  static Type GetTypeFromName(const std::string& name);

  static std::string GetNameFromType(Type type);

  static bool HasIV(Type type);

  static int GetOutputSize(Type type, int block_size, int input_length);

 private:
  CipherMode();

  DISALLOW_COPY_AND_ASSIGN(CipherMode);
};

}  // namespace keyczar

#endif  // KEYCZAR_CIPHER_MODE_H_
