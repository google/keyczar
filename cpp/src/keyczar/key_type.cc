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
#include "keyczar/key_type.h"

#include <algorithm>

#include "base/logging.h"

namespace keyczar {

KeyType::KeyType(Type type, int output_size, const std::vector<int>& sizes,
                 int default_size)
    : type_(type), output_size_(output_size), sizes_(sizes),
      default_size_(default_size) {
  DCHECK(IsValidSize(default_size_));
}

// static
KeyType* KeyType::Create(const std::string& name) {
  std::vector<int> sizes;
  if (name.compare("AES") == 0) {
    sizes.push_back(128);
    sizes.push_back(192);
    sizes.push_back(256);
    return new KeyType(AES,
                       0,  /* output_size */
                       sizes,
                       128);  /* default_size */
  }
  if (name.compare("HMAC_SHA1") == 0) {
    sizes.push_back(256);
    return new KeyType(HMAC_SHA1, 20, sizes, 256);
  }
  if (name.compare("DSA_PRIV") == 0) {
    sizes.push_back(1024);
    return new KeyType(DSA_PRIV, 48, sizes, 1024);
  }
  if (name.compare("DSA_PUB") == 0) {
    sizes.push_back(1024);
    return new KeyType(DSA_PUB, 48, sizes, 1024);
  }
  if (name.compare("RSA_PRIV") == 0) {
    sizes.push_back(2048);
    sizes.push_back(1024);
    sizes.push_back(768);
    sizes.push_back(512);
    return new KeyType(RSA_PRIV, 256, sizes, 2048);
  }
  if (name.compare("RSA_PUB") == 0) {
    sizes.push_back(2048);
    sizes.push_back(1024);
    sizes.push_back(768);
    sizes.push_back(512);
    return new KeyType(RSA_PUB, 256, sizes, 2048);
  }
  NOTREACHED();
  return NULL;
}

bool KeyType::GetName(std::string* name) const {
  if (name == NULL)
    return false;

  switch (type_) {
    case AES:
      name->assign("AES");
      return true;
    case HMAC_SHA1:
      name->assign("HMAC_SHA1");
      return true;
    case DSA_PRIV:
      name->assign("DSA_PRIV");
      return true;
    case DSA_PUB:
      name->assign("DSA_PUB");
      return true;
    case RSA_PRIV:
      name->assign("RSA_PRIV");
      return true;
    case RSA_PUB:
      name->assign("RSA_PUB");
      return true;
    default:
      NOTREACHED();
  }
  return false;
}

bool KeyType::IsValidSize(int size) const {
  return std::find(sizes_.begin(), sizes_.end(), size) != sizes_.end();
}

}  // namespace keyczar
