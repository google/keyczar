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
#include <keyczar/key_purpose.h>

#include <keyczar/base/logging.h>

namespace keyczar {

// static
KeyPurpose::Type KeyPurpose::GetTypeFromName(const std::string& name) {
  if (name == "DECRYPT_AND_ENCRYPT")
    return DECRYPT_AND_ENCRYPT;
  if (name == "ENCRYPT")
    return ENCRYPT;
  if (name == "SIGN_AND_VERIFY")
    return SIGN_AND_VERIFY;
  if (name == "VERIFY")
    return VERIFY;

  NOTREACHED();
  return UNDEF;
}

// static
std::string KeyPurpose::GetNameFromType(Type type) {
  switch (type) {
    case DECRYPT_AND_ENCRYPT:
      return "DECRYPT_AND_ENCRYPT";
    case ENCRYPT:
      return "ENCRYPT";
    case SIGN_AND_VERIFY:
      return "SIGN_AND_VERIFY";
    case VERIFY:
      return "VERIFY";
    default:
      NOTREACHED();
  }
  return "";
}

}  // namespace keyczar
