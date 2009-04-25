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
#include "keyczar/hmac_key.h"

#include "base/base64w.h"
#include "base/logging.h"

#include "keyczar/crypto_factory.h"
#include "keyczar/key_util.h"
#include "keyczar/message_digest_impl.h"

namespace keyczar {

// static
HMACKey* HMACKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* hmac_key = static_cast<const DictionaryValue*>(
      &root_key);

  std::string key;
  if (!util::DeserializeString(*hmac_key, L"hmacKeyString", &key))
    return NULL;

  int size;
  if (!hmac_key->GetInteger(L"size", &size))
    return NULL;

  if (size / 8 != static_cast<int>(key.length())) {
    LOG(ERROR) << "Mismatch between key string length and declared size";
    return NULL;
  }

  scoped_ptr<HMACImpl> hmac_key_impl(
      CryptoFactory::CreateHMACSHA1(key));
  if (hmac_key_impl.get() == NULL)
    return NULL;

  return new HMACKey(hmac_key_impl.release());
}

// static
HMACKey* HMACKey::GenerateKey(int size) {
  scoped_ptr<KeyType> key_type(KeyType::Create("HMAC_SHA1"));
  if (key_type.get() == NULL)
    return NULL;

  if (!key_type->IsValidSize(size)) {
    LOG(ERROR) << "Invalid key size: " << size;
    return NULL;
  }

  if (size < key_type->default_size())
    LOG(WARNING) << "Key size ("
                 << size
                 << ") shorter than recommanded ("
                 << key_type->default_size()
                 << "), might be unsecure";

  scoped_ptr<HMACImpl> hmac_key_impl(
      CryptoFactory::GenerateHMACSHA1(size));
  if (hmac_key_impl.get() == NULL)
    return NULL;

  return new HMACKey(hmac_key_impl.release());
}

Value* HMACKey::GetValue() const {
  if (hmac_impl_.get() == NULL)
    return NULL;

  scoped_ptr<DictionaryValue> hmac_key(new DictionaryValue);
  if (hmac_key.get() == NULL)
    return NULL;

  if (!util::SerializeString(hmac_impl_->GetKey(), L"hmacKeyString",
                             hmac_key.get()))
    return NULL;

  if (!hmac_key->SetInteger(L"size", hmac_impl_->GetKey().length() * 8))
    return NULL;

  return hmac_key.release();
}

bool HMACKey::Hash(std::string* hash) const {
  if (hash == NULL || hmac_impl_.get() == NULL)
    return false;

  MessageDigestImpl* digest_impl = CryptoFactory::SHA1();
  if (digest_impl == NULL)
    return false;

  // Builds a message digest based on the secret key
  std::string full_hash;
  digest_impl->Digest(hmac_impl_->GetKey(), &full_hash);
  DCHECK(Key::GetHashSize() <= static_cast<int>(full_hash.length()));

  Base64WEncode(full_hash.substr(0, Key::GetHashSize()), hash);
  return true;
}

const KeyType* HMACKey::GetType() const {
  static const KeyType* key_type = KeyType::Create("HMAC_SHA1");
  return key_type;
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

  return digest == signature;
}

}  // namespace keyczar
