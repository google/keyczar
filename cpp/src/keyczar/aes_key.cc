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
#include <keyczar/aes_key.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/key_util.h>
#include <keyczar/message_digest_impl.h>
#include <keyczar/rand_impl.h>

namespace {

// This function returns 0 if it fails.
static int GetHMACSizeFromAESSize(int size) {
#ifdef COMPAT_KEYCZAR_06B
  return 160;
#else
  // These choices follow the NIST recommendations, see SP800-57 part1
  // pages 63-64.
  int hmac_size = 0;
  switch (size) {
    case 128:
      hmac_size = 160;
      break;
    case 192:
      hmac_size = 224;
      break;
    case 256:
      hmac_size = 256;
      break;
    default:
      NOTREACHED();
  }
  return hmac_size;
#endif
}

}  // namespace

namespace keyczar {

// static
AESKey* AESKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* aes_key = static_cast<const DictionaryValue*>(
      &root_key);

  std::string mode;
  if (!aes_key->GetString("mode", &mode))
    return NULL;

  CipherMode::Type cipher_mode = CipherMode::GetTypeFromName(mode);
  if (cipher_mode == CipherMode::UNDEF)
    return NULL;

  base::ScopedSafeString aes_key_string(new std::string());
  if (!util::SafeDeserializeString(*aes_key, "aesKeyString",
                                   aes_key_string.get()))
    return NULL;

  int size;
  if (!aes_key->GetInteger("size", &size))
    return NULL;

  if (size / 8 != static_cast<int>(aes_key_string->size())) {
    LOG(ERROR) << "Mismatch between key string length and declared size";
    return NULL;
  }

  if (!KeyType::IsValidCipherSize(KeyType::AES, size))
    return NULL;

  DictionaryValue* hmac_key_value = NULL;
  if (!aes_key->GetDictionary("hmacKey", &hmac_key_value))
    return NULL;

  if (hmac_key_value == NULL)
    return NULL;

  scoped_ptr<AESImpl> aes_key_impl(
      CryptoFactory::CreateAES(cipher_mode, *aes_key_string));
  if (aes_key_impl.get() == NULL)
    return NULL;

  scoped_refptr<HMACKey> hmac_key = HMACKey::CreateFromValue(*hmac_key_value);
  if (hmac_key == NULL)
    return NULL;

  if (GetHMACSizeFromAESSize(size) != hmac_key->size()) {
    LOG(ERROR) << "Incompatibles key sizes between AES key and HMAC key.";
    return NULL;
  }

  return new AESKey(aes_key_impl.release(), cipher_mode, size, hmac_key);
}

// static
AESKey* AESKey::GenerateKey(int size) {
  if (!KeyType::IsValidCipherSize(KeyType::AES, size))
    return NULL;

  // Currently only CBC mode is supported, so only CBC keys are generated.
  CipherMode::Type cipher_mode = CipherMode::CBC;

  scoped_ptr<AESImpl> aes_key_impl(CryptoFactory::GenerateAES(cipher_mode,
                                                              size));
  if (aes_key_impl.get() == NULL)
    return NULL;

  int hmac_size = GetHMACSizeFromAESSize(size);
  if (hmac_size == 0)
    return NULL;

  HMACKey* hmac_key = HMACKey::GenerateKey(hmac_size);
  if (hmac_key == NULL)
    return NULL;

  return new AESKey(aes_key_impl.release(), cipher_mode, size, hmac_key);
}

Value* AESKey::GetValue() const {
  if (aes_impl_.get() == NULL || hmac_key() == NULL)
    return NULL;

  scoped_ptr<DictionaryValue> aes_key(new DictionaryValue);
  if (aes_key.get() == NULL)
    return NULL;

  std::string mode = CipherMode::GetNameFromType(cipher_mode_);
  if (mode.empty())
    return NULL;
  if (!aes_key->SetString("mode", mode))
    return NULL;

  if (!util::SafeSerializeString(aes_impl_->GetKey(), "aesKeyString",
                                 aes_key.get()))
    return NULL;

  if (!aes_key->SetInteger("size", size()))
    return NULL;

  Value* hmac_key_value = hmac_key()->GetValue();
  if (hmac_key_value == NULL)
    return NULL;

  if (!aes_key->Set("hmacKey", hmac_key_value))
    return NULL;

  return aes_key.release();
}

bool AESKey::ComputeHash(std::string* hash, bool buggy) const {
  if (hash == NULL || aes_impl_.get() == NULL || hmac_key() == NULL ||
      hmac_key()->hmac_impl() == NULL)
    return false;

  // The buggy hash is only distinct from the correct hash when the key
  // has one or more leading zero bytes.
  if (buggy && aes_impl_->GetKey()[0] != 0) {
    return false;
  }

  scoped_ptr<MessageDigestImpl> digest_impl(CryptoFactory::SHA1());
  if (digest_impl.get() == NULL)
    return false;

  digest_impl->Init();
  AddToHash(aes_impl_->GetKey(), *digest_impl, buggy);
  digest_impl->Update(hmac_key()->hmac_impl()->GetKey());
  std::string full_hash;
  digest_impl->Final(&full_hash);
  CHECK_LE(Key::GetHashSize(), static_cast<int>(full_hash.length()));

  base::Base64WEncode(full_hash.substr(0, Key::GetHashSize()), hash);
  return true;
}

bool AESKey::Hash(std::string* hash) const {
  return ComputeHash(hash, false);
}

bool AESKey::BuggyHash(std::string* hash) const {
  return ComputeHash(hash, true);
}

bool AESKey::Encrypt(const std::string& plaintext,
                     std::string* ciphertext) const {
  if (ciphertext == NULL || aes_impl_.get() == NULL || hmac_key() == NULL)
    return false;

  std::string encrypted_plaintext;
  std::string iv;
  if (!aes_impl_->Encrypt(plaintext, &encrypted_plaintext, &iv))
    return false;

  // Fixme: trick to provide same data format than Java implementation.
  // AES use an IV size equals to its block size but for preserving the
  // compatibilty with Java implementation the IV is serialized on the
  // key length bytes. The rightmost bytes should not be considered by
  // mains AES implementations (including OpenSSL). These implementations
  // use a block size of 16 bytes even for AES 192 and AES 256. When an IV
  // of 32 bytes used with AES 256 is transmitted to OpenSSL, only its 16
  // first bytes are effectively, ignoring the last 16 bytes.
  if (iv.length() < aes_impl_->GetKey().length())
    iv.append(aes_impl_->GetKey().length() - iv.length(), '\0');

  std::string header;
  if (!Header(&header))
    return false;

  std::string all_bytes = header + iv + encrypted_plaintext;

  std::string signature;
  if (!hmac_key()->Sign(all_bytes, &signature))
    return false;

  ciphertext->assign(all_bytes + signature);
  return true;
}

bool AESKey::Decrypt(const std::string& ciphertext,
                     std::string* plaintext) const {
  if (plaintext == NULL || aes_impl_.get() == NULL || hmac_key() == NULL)
    return false;

  int key_size = size() / 8;
  int digest_size = hmac_key()->size() / 8;

  std::string data_bytes = ciphertext.substr(Key::GetHeaderSize());
  int data_bytes_len = data_bytes.length();

  std::string iv_bytes = data_bytes.substr(0, key_size);
  std::string aes_bytes = data_bytes.substr(
      key_size, data_bytes_len - digest_size - key_size);
  std::string signature_bytes = data_bytes.substr(data_bytes_len - digest_size);

  if (!hmac_key()->Verify(
          ciphertext.substr(0, ciphertext.length() - digest_size),
          signature_bytes))
    return false;

  if (!aes_impl_->Decrypt(iv_bytes, aes_bytes, plaintext))
    return false;

  return true;
}

}  // namespace keyczar
