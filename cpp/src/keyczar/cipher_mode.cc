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
#include "keyczar/cipher_mode.h"

#include "base/logging.h"

namespace keyczar {

// static
CipherMode* CipherMode::Create(const std::string& name) {
  if (name.compare("CBC") == 0)
    return new CipherMode(CBC, true /* use_iv */);
  if (name.compare("CTR") == 0)
    return new CipherMode(CTR, true);
  if (name.compare("ECB") == 0)
    return new CipherMode(ECB, false);
  if (name.compare("DET_CBC") == 0)
    return new CipherMode(DET_CBC, false);
  NOTREACHED();
  return NULL;
}

bool CipherMode::GetName(std::string* name) const {
  if (name == NULL)
    return false;

  switch (type_) {
    case CBC:
      name->assign("CBC");
      return true;
    case CTR:
      name->assign("CTR");
      return true;
    case ECB:
      name->assign("ECB");
      return true;
    case DET_CBC:
      name->assign("DET_CBC");
      return true;
    default:
      NOTREACHED();
  }
  return false;
}

int CipherMode::GetOutputSize(int block_size, int input_length) const {
  if (type_ == CBC) {
    return (input_length / block_size + 2) * block_size;
  } else {
    if (type_ == ECB) {
      return block_size;
    } else {
      if (type_ == CTR) {
        return input_length + block_size / 2;
      } else {
        if (type_ == DET_CBC) {
          return (input_length / block_size + 1) * block_size;
        }
      }
    }
  }
  NOTREACHED();
  return 0;
}

}  // namespace keyczar
