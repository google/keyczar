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
#include "keyczar/key.h"

#include "base/base64w.h"
#include "base/logging.h"

#include "keyczar/aes_key.h"
#include "keyczar/dsa_private_key.h"
#include "keyczar/dsa_public_key.h"
#include "keyczar/ecdsa_private_key.h"
#include "keyczar/ecdsa_public_key.h"
#include "keyczar/hmac_key.h"
#include "keyczar/message_digest_impl.h"
#include "keyczar/rsa_private_key.h"
#include "keyczar/rsa_public_key.h"

namespace {

// Current Keyczar version byte.
static const char kVersionByte = '\x00';

// Represents the length of the hash calculated for each key.
static const int kKeyHashSize = 4;

void Int32ToByteArray(int32 num, unsigned char* array) {
  unsigned char current_byte;

  for (int i = 0; i < 4; ++i) {
    current_byte = (num >> ((i & 7) << 3)) & 0xFF;
    array[4 - i - 1] = current_byte;
  }
}

}  // namespace

namespace keyczar {

// static
Key* Key::CreateFromValue(const KeyType& key_type, const Value& root) {
  switch (key_type.type()) {
    case KeyType::AES:
      return AESKey::CreateFromValue(root);
#ifdef COMPAT_KEYCZAR_06B
    case KeyType::HMAC_SHA1:
#else
    case KeyType::HMAC:
#endif
      return HMACKey::CreateFromValue(root);
    case KeyType::DSA_PRIV:
      return DSAPrivateKey::CreateFromValue(root);
    case KeyType::DSA_PUB:
      return DSAPublicKey::CreateFromValue(root);
    case KeyType::ECDSA_PRIV:
      return ECDSAPrivateKey::CreateFromValue(root);
    case KeyType::ECDSA_PUB:
      return ECDSAPublicKey::CreateFromValue(root);
    case KeyType::RSA_PRIV:
      return RSAPrivateKey::CreateFromValue(root);
    case KeyType::RSA_PUB:
      return RSAPublicKey::CreateFromValue(root);
    default:
      NOTREACHED();
  }
  return NULL;
}

// static
Key* Key::GenerateKey(const KeyType& key_type, int size) {
  switch (key_type.type()) {
    case KeyType::AES:
      return AESKey::GenerateKey(size);
#ifdef COMPAT_KEYCZAR_06B
    case KeyType::HMAC_SHA1:
#else
    case KeyType::HMAC:
#endif
      return HMACKey::GenerateKey(size);
    case KeyType::DSA_PRIV:
      return DSAPrivateKey::GenerateKey(size);
    case KeyType::ECDSA_PRIV:
      return ECDSAPrivateKey::GenerateKey(size);
    case KeyType::RSA_PRIV:
      return RSAPrivateKey::GenerateKey(size);
    case KeyType::DSA_PUB:
    case KeyType::ECDSA_PUB:
    case KeyType::RSA_PUB:
      LOG(ERROR) << "Public keys must be exported from private keys";
      return NULL;
    default:
      NOTREACHED();
  }
  return NULL;
}

// static
Key* Key::CreateFromPEMKey(const KeyType& key_type,
                           const std::string& filename,
                           const std::string* passphrase) {
  switch (key_type.type()) {
    case KeyType::DSA_PRIV:
      return DSAPrivateKey::CreateFromPEMKey(filename, passphrase);
    case KeyType::ECDSA_PRIV:
      return ECDSAPrivateKey::CreateFromPEMKey(filename, passphrase);
    case KeyType::RSA_PRIV:
      return RSAPrivateKey::CreateFromPEMKey(filename, passphrase);
#ifdef COMPAT_KEYCZAR_06B
    case KeyType::HMAC_SHA1:
#else
    case KeyType::HMAC:
#endif
    case KeyType::AES:
    case KeyType::DSA_PUB:
    case KeyType::ECDSA_PUB:
    case KeyType::RSA_PUB:
      LOG(ERROR) << "Only private keys are imported from PEM keys";
      return NULL;
    default:
      NOTREACHED();
  }
  return NULL;
}

Value* Key::GetPublicKeyValue() const {
  return NULL;
}

bool Key::Sign(const std::string& data, std::string* signature) const {
  return false;
}

bool Key::Verify(const std::string& data,
                 const std::string& signature) const {
  return false;
}

bool Key::Encrypt(const std::string& data,
                  std::string* encrypted) const {
  return false;
}

bool Key::Decrypt(const std::string& encrypted,
                         std::string* data) const {
  return false;
}

// Static
int Key::GetHashSize() {
  return kKeyHashSize;
}

// Static
int Key::GetHeaderSize() {
  return 1 + Key::GetHashSize();
}

// Static
char Key::GetVersionByte() {
  return kVersionByte;
}

bool Key::Header(std::string* header) const {
  if (header == NULL)
    return false;

  std::string hash;
  if (!Hash(&hash))
    return false;

  std::string decoded;
  if (!Base64WDecode(hash, &decoded))
    return false;

  header->clear();
  header->push_back(kVersionByte);
  header->append(decoded);
  return true;
}

void Key::AddToHash(const std::string& field,
                    MessageDigestImpl& digest_impl) const {
  // Removes nul leading characters
  std::string trimmed_field = field.substr(field.find_first_not_of('\0'));

  // Converts int field's length to bytes (big endian oriented)
  int32 field_length = trimmed_field.length();
  unsigned char bytes_array[sizeof(field_length)];
  Int32ToByteArray(field_length, bytes_array);
  std::string bytes(reinterpret_cast<char*>(bytes_array),
                    sizeof(field_length));

  // Update the message digest value
  digest_impl.Update(bytes);
  digest_impl.Update(trimmed_field);
}

}  // namespace keyczar
