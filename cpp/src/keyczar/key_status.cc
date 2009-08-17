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
KeyStatus::Type KeyStatus::GetTypeFromName(const std::string& name) {
  if (name == "PRIMARY")
    return PRIMARY;
  if (name == "ACTIVE")
    return ACTIVE;
  if (name == "INACTIVE")
    return INACTIVE;

  NOTREACHED();
  return UNDEF;
}

// static
std::string KeyStatus::GetNameFromType(Type type) {
  switch (type) {
    case PRIMARY:
      return "PRIMARY";
    case ACTIVE:
      return "ACTIVE";
    case INACTIVE:
      return "INACTIVE";
    default:
      NOTREACHED();
  }
  return "";
}

}  // namespace keyczar
