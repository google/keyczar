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

KeyType::KeyType(Type type, const std::vector<int>& sizes, int default_size)
    : type_(type), sizes_(sizes), default_size_(default_size) {
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
                       sizes,
                       128);  /* default_size */
  }
#ifdef COMPAT_KEYCZAR_06B
  if (name.compare("HMAC_SHA1") == 0) {
    sizes.push_back(160);
    return new KeyType(HMAC_SHA1, sizes, 160);
#else
  if (name.compare("HMAC") == 0) {
    sizes.push_back(160);
    sizes.push_back(224);
    sizes.push_back(256);
    sizes.push_back(384);
    sizes.push_back(512);
    return new KeyType(HMAC, sizes, 160);
#endif
  }
  if (name.compare("DSA_PRIV") == 0) {
    sizes.push_back(1024);
    sizes.push_back(2048);
    sizes.push_back(3072);
    return new KeyType(DSA_PRIV, sizes, 2048);
  }
  if (name.compare("DSA_PUB") == 0) {
    sizes.push_back(1024);
    sizes.push_back(2048);
    sizes.push_back(3072);
    return new KeyType(DSA_PUB, sizes, 2048);
  }
  if (name.compare("ECDSA_PRIV") == 0) {
    sizes.push_back(192);
    sizes.push_back(224);
    sizes.push_back(256);
    sizes.push_back(384);
    return new KeyType(ECDSA_PRIV, sizes, 224);
  }
  if (name.compare("ECDSA_PUB") == 0) {
    sizes.push_back(192);
    sizes.push_back(224);
    sizes.push_back(256);
    sizes.push_back(384);
    return new KeyType(ECDSA_PUB, sizes, 224);
  }
  if (name.compare("RSA_PRIV") == 0) {
#ifdef COMPAT_KEYCZAR_06B
    sizes.push_back(512);
    sizes.push_back(768);
#endif
    sizes.push_back(1024);
    sizes.push_back(2048);
    sizes.push_back(3072);
    return new KeyType(RSA_PRIV, sizes, 2048);
  }
  if (name.compare("RSA_PUB") == 0) {
#ifdef COMPAT_KEYCZAR_06B
    sizes.push_back(512);
    sizes.push_back(768);
#endif
    sizes.push_back(1024);
    sizes.push_back(2048);
    sizes.push_back(3072);
    return new KeyType(RSA_PUB, sizes, 2048);
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
#ifdef COMPAT_KEYCZAR_06B
    case HMAC_SHA1:
      name->assign("HMAC_SHA1");
#else
    case HMAC:
      name->assign("HMAC");
#endif
      return true;
    case DSA_PRIV:
      name->assign("DSA_PRIV");
      return true;
    case DSA_PUB:
      name->assign("DSA_PUB");
      return true;
    case ECDSA_PRIV:
      name->assign("ECDSA_PRIV");
      return true;
    case ECDSA_PUB:
      name->assign("ECDSA_PUB");
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

bool IsValidSize(const std::string& key_type_name, int size) {
  scoped_ptr<KeyType> key_type(KeyType::Create(key_type_name));
  if (key_type.get() == NULL)
    return false;

  if (!key_type->IsValidSize(size)) {
    LOG(ERROR) << "Invalid key size: " << size;
    return false;
  }

  if (size < key_type->default_size())
    LOG(WARNING) << "Key size ("
                 << size
                 << ") shorter than recommanded ("
                 << key_type->default_size()
                 << "), might be unsecure";

  return true;
}

}  // namespace keyczar
