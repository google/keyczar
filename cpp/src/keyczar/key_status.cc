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
#include <keyczar/key_status.h>

#include <keyczar/base/logging.h>

namespace keyczar {

// static
KeyStatus* KeyStatus::Create(const std::string& name) {
  if (name.compare("PRIMARY") == 0)
    return new KeyStatus(PRIMARY);
  if (name.compare("ACTIVE") == 0)
    return new KeyStatus(ACTIVE);
  if (name.compare("INACTIVE") == 0)
    return new KeyStatus(INACTIVE);
  NOTREACHED();
  return NULL;
}

bool KeyStatus::GetName(std::string* name) const {
  if (name == NULL)
    return false;

  switch (type_) {
    case PRIMARY:
      name->assign("PRIMARY");
      return true;
    case ACTIVE:
      name->assign("ACTIVE");
      return true;
    case INACTIVE:
      name->assign("INACTIVE");
      return true;
    default:
      NOTREACHED();
  }
  return false;
}

}  // namespace keyczar
