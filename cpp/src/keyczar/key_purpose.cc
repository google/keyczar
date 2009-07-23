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
KeyPurpose* KeyPurpose::Create(const std::string& name) {
  if (name.compare("DECRYPT_AND_ENCRYPT") == 0)
    return new KeyPurpose(DECRYPT_AND_ENCRYPT);
  if (name.compare("ENCRYPT") == 0)
    return new KeyPurpose(ENCRYPT);
  if (name.compare("SIGN_AND_VERIFY") == 0)
    return new KeyPurpose(SIGN_AND_VERIFY);
  if (name.compare("VERIFY") == 0)
    return new KeyPurpose(VERIFY);
  NOTREACHED();
  return NULL;
}

bool KeyPurpose::GetName(std::string* name) const {
  if (name == NULL)
    return false;

  switch (type_) {
    case DECRYPT_AND_ENCRYPT:
      name->assign("DECRYPT_AND_ENCRYPT");
      return true;
    case ENCRYPT:
      name->assign("ENCRYPT");
      return true;
    case SIGN_AND_VERIFY:
      name->assign("SIGN_AND_VERIFY");
      return true;
    case VERIFY:
      name->assign("VERIFY");
      return true;
    default:
      NOTREACHED();
  }
  return false;
}

}  // namespace keyczar
