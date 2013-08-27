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
#include <keyczar/hmac_key.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/key_util.h>
#include <keyczar/message_digest_impl.h>
#include <keyczar/util.h>

namespace {

static bool GetDigestNameFromHMACKeySize(int size, std::string* name) {
  if (name == NULL)
    return false;

  switch (size) {
    case 160:
      name->assign("SHA1");
      return true;
    case 224:
      name->assign("SHA224");
      return true;
    case 256:
      name->assign("SHA256");
      return true;
    case 384:
      name->assign("SHA384");
      return true;
    case 512:
      name->assign("SHA512");
      return true;
    default:
      NOTREACHED();
  }
  return false;
}

}  // namespace

namespace keyczar {

// static
HMACKey* HMACKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* hmac_key = static_cast<const DictionaryValue*>(
      &root_key);

  base::ScopedSafeString key(new std::string());
  if (!util::SafeDeserializeString(*hmac_key, "hmacKeyString", key.get()))
    return NULL;

  int size;
  if (!hmac_key->GetInteger("size", &size))
    return NULL;

#ifdef COMPAT_KEYCZAR_06B
  CHECK_EQ(size, 256);
  size = 160;

  if (!KeyType::IsValidCipherSize(KeyType::HMAC_SHA1, size))
    return NULL;
#else
  if (size / 8 != static_cast<int>(key->size())) {
    LOG(ERROR) << "Mismatch between key string length and declared size";
    return NULL;
  }

  if (!KeyType::IsValidCipherSize(KeyType::HMAC, size))
    return NULL;

  std::string digest_name;
  if (!hmac_key->GetString("digest", &digest_name))
    return NULL;

  std::string digest_name_check;
  if (!GetDigestNameFromHMACKeySize(size, &digest_name_check))
    return NULL;
  if (digest_name != digest_name_check)
    return NULL;
#endif

  scoped_ptr<HMACImpl> hmac_key_impl(CryptoFactory::CreateHMAC(*key));
  if (hmac_key_impl.get() == NULL)
    return NULL;

  return new HMACKey(hmac_key_impl.release(), size);
}

// static
HMACKey* HMACKey::GenerateKey(int size) {
#ifdef COMPAT_KEYCZAR_06B
  CHECK_EQ(size, 160);
  if (!KeyType::IsValidCipherSize(KeyType::HMAC_SHA1, size))
#else
  if (!KeyType::IsValidCipherSize(KeyType::HMAC, size))
#endif
    return NULL;

  scoped_ptr<HMACImpl> hmac_key_impl(CryptoFactory::GenerateHMAC(size));
  if (hmac_key_impl.get() == NULL)
    return NULL;

  return new HMACKey(hmac_key_impl.release(), size);
}

Value* HMACKey::GetValue() const {
  if (hmac_impl_.get() == NULL)
    return NULL;

  scoped_ptr<DictionaryValue> hmac_key(new DictionaryValue);
  if (hmac_key.get() == NULL)
    return NULL;

  if (!util::SafeSerializeString(hmac_impl_->GetKey(), "hmacKeyString",
                                 hmac_key.get()))
    return NULL;

#ifdef COMPAT_KEYCZAR_06B
  CHECK_EQ(size(), 160);
  if (!hmac_key->SetInteger("size", 256))
#else
  std::string digest_name;
  if (!GetDigestNameFromHMACKeySize(size(), &digest_name))
    return NULL;
  if (!hmac_key->SetString("digest", digest_name))
    return NULL;

  if (!hmac_key->SetInteger("size", size()))
#endif
    return NULL;

  return hmac_key.release();
}

bool HMACKey::Hash(std::string* hash) const {
  if (hash == NULL || hmac_impl_.get() == NULL)
    return false;

  scoped_ptr<MessageDigestImpl> digest_impl(CryptoFactory::SHA1());
  if (digest_impl.get() == NULL)
    return false;

  // Builds a message digest based on the secret key
  std::string full_hash;
  digest_impl->Digest(hmac_impl_->GetKey(), &full_hash);
  CHECK_LE(Key::GetHashSize(), static_cast<int>(full_hash.length()));

  base::Base64WEncode(full_hash.substr(0, Key::GetHashSize()), hash);
  return true;
}

bool HMACKey::Sign(const std::string& data, std::string* signature) const {
  if (signature == NULL || hmac_impl_.get() == NULL)
    return false;

  return hmac_impl_->Digest(data, signature);
}

bool HMACKey::Verify(const std::string& data,
                     const std::string& signature) const {
  if (hmac_impl_.get() == NULL)
    return false;

  std::string digest;
  if (!hmac_impl_->Digest(data, &digest))
    return false;

  return util::SafeStringEquals(digest, signature);
}

}  // namespace keyczar
