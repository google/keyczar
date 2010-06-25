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
#include <keyczar/key_type.h>

#include <algorithm>

#include <keyczar/base/logging.h>
#include <keyczar/base/scoped_ptr.h>

namespace {

static const int kAESSizes[] = {128, 192, 256, 0};
#ifdef COMPAT_KEYCZAR_06B
static const int kHMACSHA1Sizes[] = {160, 0};
static const int kRSASizes[] = {512, 768, 1024, 2048, 3072, 4096, 0};
#else
static const int kHMACSizes[] = {160, 224, 256, 384, 512, 0};
static const int kRSASizes[] = {1024, 2048, 3072, 4096, 0};
#endif
static const int kDSASizes[] = {1024, 2048, 3072, 0};
static const int kECDSASizes[] = {192, 224, 256, 384, 0};

// static
const int* CipherSizesArray(keyczar::KeyType::Type type) {
  switch (type) {
    case keyczar::KeyType::AES:
      return kAESSizes;
#ifdef COMPAT_KEYCZAR_06B
    case keyczar::KeyType::HMAC_SHA1:
      return kHMACSHA1Sizes;
    case keyczar::KeyType::RSA_PRIV:
    case keyczar::KeyType::RSA_PUB:
      return kRSASizes;
#else
    case keyczar::KeyType::HMAC:
      return kHMACSizes;
    case keyczar::KeyType::RSA_PRIV:
    case keyczar::KeyType::RSA_PUB:
      return kRSASizes;
#endif
    case keyczar::KeyType::DSA_PRIV:
    case keyczar::KeyType::DSA_PUB:
      return kDSASizes;
    case keyczar::KeyType::ECDSA_PRIV:
    case keyczar::KeyType::ECDSA_PUB:
      return kECDSASizes;
    default:
      NOTREACHED();
  }
  return NULL;
}

}  // namespace

namespace keyczar {

// static
KeyType::Type KeyType::GetTypeFromName(const std::string& name) {
  if (name == "AES")
    return AES;
#ifdef COMPAT_KEYCZAR_06B
  if (name == "HMAC_SHA1")
    return HMAC_SHA1;
#else
  if (name == "HMAC")
    return HMAC;
#endif
  if (name == "DSA_PRIV")
    return DSA_PRIV;
  if (name == "DSA_PUB")
    return DSA_PUB;
  if (name == "ECDSA_PRIV")
    return ECDSA_PRIV;
  if (name == "ECDSA_PUB")
    return ECDSA_PUB;
  if (name == "RSA_PRIV")
    return RSA_PRIV;
  if (name == "RSA_PUB")
    return RSA_PUB;

  NOTREACHED();
  return UNDEF;
}

// static
std::string KeyType::GetNameFromType(Type type) {
  switch (type) {
    case AES:
      return "AES";
#ifdef COMPAT_KEYCZAR_06B
    case HMAC_SHA1:
      return "HMAC_SHA1";
#else
    case HMAC:
      return "HMAC";
#endif
    case DSA_PRIV:
      return "DSA_PRIV";
    case DSA_PUB:
      return "DSA_PUB";
    case ECDSA_PRIV:
      return "ECDSA_PRIV";
    case ECDSA_PUB:
      return "ECDSA_PUB";
    case RSA_PRIV:
      return "RSA_PRIV";
    case RSA_PUB:
      return "RSA_PUB";
    default:
      NOTREACHED();
  }
  return "";
}

// static
int KeyType::DefaultCipherSize(Type type) {
  switch (type) {
    case AES:
      return 128;
#ifdef COMPAT_KEYCZAR_06B
    case HMAC_SHA1:
      return 160;
#else
    case HMAC:
      return 160;
#endif
    case DSA_PRIV:
    case DSA_PUB:
      return 2048;
    case ECDSA_PRIV:
    case ECDSA_PUB:
      return 224;
    case RSA_PRIV:
    case RSA_PUB:
      return 2048;
    default:
      NOTREACHED();
  }
  return 0;
}

// static
bool KeyType::IsValidCipherSize(Type type, int size) {
  int i = 0;
  const int* sizes_ptr = CipherSizesArray(type);
  if (sizes_ptr == NULL)
    return false;

  for (; sizes_ptr[i] != 0; ++i)
    if (sizes_ptr[i] == size)
      break;

  if (sizes_ptr[i] == 0) {
    LOG(ERROR) << "Invalid key size: " << size;
    return false;
  }

  if (size < KeyType::DefaultCipherSize(type))
    LOG(WARNING) << "Key size of size "
                 << size
                 << " bits is shorter than recommanded ("
                 << KeyType::DefaultCipherSize(type)
                 << " bits).";
  return true;
}

// static
std::vector<int> KeyType::CipherSizes(Type type) {
  std::vector<int> vec;
  const int* sizes_ptr = CipherSizesArray(type);

  for (int i = 0; sizes_ptr[i] != 0; ++i)
    vec.push_back(sizes_ptr[i]);
  return vec;
}


}  // namespace keyczar
