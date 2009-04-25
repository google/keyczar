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
#include "keyczar/aes_key.h"

#include "base/base64w.h"
#include "base/logging.h"

#include "keyczar/crypto_factory.h"
#include "keyczar/key_util.h"
#include "keyczar/message_digest_impl.h"
#include "keyczar/rand_impl.h"

namespace keyczar {

// static
AESKey* AESKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* aes_key = static_cast<const DictionaryValue*>(
      &root_key);

  std::string mode;
  if (!aes_key->GetString(L"mode", &mode))
    return NULL;

  scoped_ptr<CipherMode> cipher_mode(CipherMode::Create(mode));
  if (cipher_mode.get() == NULL)
    return NULL;

  std::string aes_key_string;
  if (!util::DeserializeString(*aes_key, L"aesKeyString", &aes_key_string))
    return NULL;

  int size;
  if (!aes_key->GetInteger(L"size", &size))
    return NULL;

  if (size / 8 != static_cast<int>(aes_key_string.length())) {
    LOG(ERROR) << "Mismatch between key string length and declared size";
    return NULL;
  }

  DictionaryValue* hmac_key_value = NULL;
  if (!aes_key->GetDictionary(L"hmacKey", &hmac_key_value))
    return NULL;

  if (hmac_key_value == NULL)
    return NULL;

  scoped_ptr<AESImpl> aes_key_impl(
      CryptoFactory::CreateAES(*cipher_mode, aes_key_string));
  if (aes_key_impl.get() == NULL)
    return NULL;

  HMACKey* hmac_key = HMACKey::CreateFromValue(*hmac_key_value);
  if (hmac_key == NULL)
    return NULL;

  return new AESKey(aes_key_impl.release(), cipher_mode.release(), hmac_key);
}

// static
AESKey* AESKey::GenerateKey(int size) {
  scoped_ptr<KeyType> aes_type(KeyType::Create("AES"));
  if (aes_type.get() == NULL)
    return NULL;

  if (!aes_type->IsValidSize(size)) {
    LOG(ERROR) << "Invalid key size: " << size;
    return NULL;
  }

  if (size < aes_type->default_size())
    LOG(WARNING) << "Key size ("
                 << size
                 << ") shorter than recommanded ("
                 << aes_type->default_size()
                 << "), might be unsecure";

  // Currently only CBC mode is supported, so only CBC keys are generated.
  scoped_ptr<CipherMode> cipher_mode(CipherMode::Create("CBC"));
  if (cipher_mode.get() == NULL)
    return NULL;

  scoped_ptr<AESImpl> aes_key_impl(
      CryptoFactory::GenerateAES(*cipher_mode, size));
  if (aes_key_impl.get() == NULL)
    return NULL;

  scoped_ptr<KeyType> hmac_type(KeyType::Create("HMAC_SHA1"));
  if (hmac_type.get() == NULL)
    return NULL;

  // The HMAC key is generated from its default size.
  HMACKey* hmac_key = HMACKey::GenerateKey(hmac_type->default_size());
  if (hmac_key == NULL)
    return NULL;

  return new AESKey(aes_key_impl.release(), cipher_mode.release(), hmac_key);
}

Value* AESKey::GetValue() const {
  if (aes_impl_.get() == NULL || hmac_key() == NULL ||
      cipher_mode_.get() == NULL)
    return false;

  scoped_ptr<DictionaryValue> aes_key(new DictionaryValue);
  if (aes_key.get() == NULL)
    return NULL;

  std::string mode;
  if (!cipher_mode_->GetName(&mode))
    return NULL;
  if (!aes_key->SetString(L"mode", mode))
    return NULL;

  if (!util::SerializeString(aes_impl_->GetKey(), L"aesKeyString",
                             aes_key.get()))
    return NULL;

  if (!aes_key->SetInteger(L"size", aes_impl_->GetKey().length() * 8))
    return NULL;

  Value* hmac_key_value = hmac_key()->GetValue();
  if (hmac_key_value == NULL)
    return NULL;

  if (!aes_key->Set(L"hmacKey", hmac_key_value))
    return NULL;

  return aes_key.release();
}

bool AESKey::Hash(std::string* hash) const {
  if (hash == NULL || aes_impl_.get() == NULL || hmac_key() == NULL ||
      hmac_key()->hmac_impl() == NULL)
    return false;

  MessageDigestImpl* digest_impl = CryptoFactory::SHA1();
  if (digest_impl == NULL)
    return false;

  digest_impl->Init();
  AddToHash(aes_impl_->GetKey(), *digest_impl);
  digest_impl->Update(hmac_key()->hmac_impl()->GetKey());
  std::string full_hash;
  digest_impl->Final(&full_hash);
  DCHECK(Key::GetHashSize() <= static_cast<int>(full_hash.length()));

  Base64WEncode(full_hash.substr(0, Key::GetHashSize()), hash);
  return true;
}

const KeyType* AESKey::GetType() const {
  static const KeyType* key_type = KeyType::Create("AES");
  return key_type;
}

bool AESKey::Encrypt(const std::string& data, std::string* encrypted) const {
  if (encrypted == NULL || aes_impl_.get() == NULL || hmac_key() == NULL)
    return false;

  RandImpl* rand_impl = CryptoFactory::Rand();
  if (rand_impl == NULL)
    return false;

  std::string iv;
  if (!rand_impl->RandBytes(aes_impl_->GetKeySize(), &iv))
    return false;
  DCHECK(iv.length() >= aes_impl_->GetKey().length());

  std::string aes_bytes;
  if (!aes_impl_->Encrypt(&iv, data, &aes_bytes))
    return false;

  std::string header;
  if (!Header(&header))
    return false;

  std::string message_bytes = header + iv + aes_bytes;

  std::string signature_bytes;
  if (!hmac_key()->Sign(message_bytes, &signature_bytes))
    return false;

  encrypted->assign(message_bytes + signature_bytes);
  return true;
}

bool AESKey::Decrypt(const std::string& encrypted, std::string* data) const {
  if (data == NULL || aes_impl_.get() == NULL || hmac_key() == NULL)
    return false;

  MessageDigestImpl* digest_impl = CryptoFactory::SHA1();
  if (digest_impl == NULL)
    return false;

  int key_size = aes_impl_->GetKeySize();
  int digest_size = digest_impl->Size();

  std::string data_bytes = encrypted.substr(Key::GetHeaderSize());
  int data_bytes_len = data_bytes.length();

  std::string iv_bytes = data_bytes.substr(0, key_size);
  std::string aes_bytes = data_bytes.substr(
      key_size, data_bytes_len - digest_size - key_size);
  std::string signature_bytes = data_bytes.substr(data_bytes_len - digest_size);

  if (!hmac_key()->Verify(
          encrypted.substr(0, encrypted.length() - digest_size),
          signature_bytes))
    return false;

  if (!aes_impl_->Decrypt(&iv_bytes, aes_bytes, data))
    return false;

  return true;
}

}  // namespace keyczar
