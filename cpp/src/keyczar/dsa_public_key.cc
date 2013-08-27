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
#include <keyczar/dsa_public_key.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/values.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/dsa_impl.h>
#include <keyczar/key_type.h>
#include <keyczar/key_util.h>
#include <keyczar/message_digest_impl.h>

namespace keyczar {

// static
DSAPublicKey* DSAPublicKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* public_key = static_cast<const DictionaryValue*>(
      &root_key);

  DSAImpl::DSAIntermediateKey intermediate_key;

  if (!util::DeserializeString(*public_key, "p", &intermediate_key.p))
    return NULL;
  if (!util::DeserializeString(*public_key, "q", &intermediate_key.q))
    return NULL;
  if (!util::DeserializeString(*public_key, "g", &intermediate_key.g))
    return NULL;
  if (!util::DeserializeString(*public_key, "y", &intermediate_key.y))
    return NULL;

  int size;
  if (!public_key->GetInteger("size", &size))
    return NULL;

  scoped_ptr<DSAImpl> dsa_public_key_impl(
      CryptoFactory::CreatePublicDSA(intermediate_key));
  if (dsa_public_key_impl.get() == NULL)
    return NULL;

  // Check the provided size is valid.
  if (size != dsa_public_key_impl->Size() ||
      !KeyType::IsValidCipherSize(KeyType::DSA_PUB, size))
    return NULL;

  return new DSAPublicKey(dsa_public_key_impl.release(), size);
}

Value* DSAPublicKey::GetValue() const {
  scoped_ptr<DictionaryValue> public_key(new DictionaryValue);
  if (public_key.get() == NULL)
    return NULL;

  DSAImpl::DSAIntermediateKey intermediate_key;
  if (!dsa_impl()->GetPublicAttributes(&intermediate_key))
    return NULL;

  if (!util::SerializeString(intermediate_key.p, "p", public_key.get()))
    return NULL;
  if (!util::SerializeString(intermediate_key.q, "q", public_key.get()))
    return NULL;
  if (!util::SerializeString(intermediate_key.g, "g", public_key.get()))
    return NULL;
  if (!util::SerializeString(intermediate_key.y, "y", public_key.get()))
    return NULL;

  if (!public_key->SetInteger("size", size()))
    return NULL;

  return public_key.release();
}

bool DSAPublicKey::Hash(std::string* hash) const {
  if (hash == NULL)
    return false;

  DSAImpl::DSAIntermediateKey key;
  if (!dsa_impl()->GetPublicAttributes(&key))
    return false;

  // Builds a message digest based on public attributes
  scoped_ptr<MessageDigestImpl> digest_impl(CryptoFactory::SHA1());
  if (digest_impl.get() == NULL)
    return false;

  digest_impl->Init();
  AddToHash(key.p, *digest_impl);
  AddToHash(key.q, *digest_impl);
  AddToHash(key.g, *digest_impl);
  AddToHash(key.y, *digest_impl);
  std::string full_hash;
  digest_impl->Final(&full_hash);
  CHECK_LE(Key::GetHashSize(), static_cast<int>(full_hash.length()));

  base::Base64WEncode(full_hash.substr(0, Key::GetHashSize()), hash);
  return true;
}

bool DSAPublicKey::Verify(const std::string& data,
                          const std::string& signature) const {
  if (dsa_impl() == NULL)
    return false;

  scoped_ptr<MessageDigestImpl> digest_impl(CryptoFactory::SHAFromFFCIFCSize(size()));
  if (digest_impl.get() == NULL)
    return false;

  std::string message_digest;
  if (!digest_impl->Digest(data, &message_digest))
    return false;

  // Cryptographic libraries like OpenSSL don't support inputs greater
  // than the size of q (ie 160 bits), so if necessary the message digest
  // value is truncated to q's length.
  DSAImpl::DSAIntermediateKey dsa_public_key;
  if (!dsa_impl()->GetPublicAttributes(&dsa_public_key))
    return false;
  // Substract 1 because intermediate representations always have a
  // leading null-byte prepended in order to conform to Java
  // implementation's format.
  const uint32 q_length = dsa_public_key.q.length() - 1;
  if (message_digest.length() > q_length)
    message_digest = message_digest.substr(0, q_length);

  return dsa_impl()->Verify(message_digest, signature);
}

}  // namespace keyczar
