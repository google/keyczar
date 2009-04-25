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
#include "keyczar/dsa_private_key.h"

#include "base/logging.h"
#include "base/values.h"

#include "keyczar/crypto_factory.h"
#include "keyczar/key_type.h"
#include "keyczar/key_util.h"

namespace keyczar {

// static
DSAPrivateKey* DSAPrivateKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* private_key = static_cast<const DictionaryValue*>(
      &root_key);

  DSAImpl::DSAIntermediateKey intermediate_key;

  if (!util::DeserializeString(*private_key, L"x", &intermediate_key.x))
    return NULL;

  int size;
  if (!private_key->GetInteger(L"size", &size))
    return NULL;

  DictionaryValue* public_key = NULL;
  if (!private_key->GetDictionary(L"publicKey", &public_key))
    return NULL;

  if (public_key == NULL)
    return NULL;

  if (!util::DeserializeString(*public_key, L"p", &intermediate_key.p))
    return NULL;
  if (!util::DeserializeString(*public_key, L"q", &intermediate_key.q))
    return NULL;
  if (!util::DeserializeString(*public_key, L"g", &intermediate_key.g))
    return NULL;
  if (!util::DeserializeString(*public_key, L"y", &intermediate_key.y))
    return NULL;

  int size_public;
  if (!public_key->GetInteger(L"size", &size_public))
    return NULL;

  DCHECK(size == size_public);

  scoped_ptr<DSAImpl> dsa_private_key_impl(
      CryptoFactory::CreatePrivateDSA(intermediate_key));
  if (dsa_private_key_impl.get() == NULL)
    return NULL;

  scoped_ptr<DSAImpl> dsa_public_key_impl(
      CryptoFactory::CreatePublicDSA(intermediate_key));
  if (dsa_public_key_impl.get() == NULL)
    return NULL;

  DSAPublicKey* dsa_public_key = new DSAPublicKey(dsa_public_key_impl.release(),
                                                  size);
  if (dsa_public_key == NULL)
    return NULL;

  return new DSAPrivateKey(dsa_private_key_impl.release(),
                           dsa_public_key,
                           size);
}

// static
DSAPrivateKey* DSAPrivateKey::GenerateKey(int size) {
  scoped_ptr<KeyType> key_type(KeyType::Create("DSA_PRIV"));
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

  scoped_ptr<DSAImpl> dsa_private_key_impl(
      CryptoFactory::GeneratePrivateDSA(size));
  if (dsa_private_key_impl.get() == NULL)
    return NULL;

  DSAImpl::DSAIntermediateKey intermediate_public_key;
  dsa_private_key_impl->GetPublicAttributes(&intermediate_public_key);

  scoped_ptr<DSAImpl> dsa_public_key_impl(
      CryptoFactory::CreatePublicDSA(intermediate_public_key));
  if (dsa_public_key_impl.get() == NULL)
    return NULL;

  DSAPublicKey* dsa_public_key = new DSAPublicKey(dsa_public_key_impl.release(),
                                                  size);
  if (dsa_public_key == NULL)
    return NULL;

  return new DSAPrivateKey(dsa_private_key_impl.release(),
                           dsa_public_key,
                           size);
}

Value* DSAPrivateKey::GetValue() const {
  scoped_ptr<DictionaryValue> private_key(new DictionaryValue);
  if (private_key.get() == NULL)
    return NULL;

  DSAImpl::DSAIntermediateKey intermediate_key;
  if (!dsa_impl()->GetAttributes(&intermediate_key))
    return NULL;

  if (!util::SerializeString(intermediate_key.x, L"x", private_key.get()))
    return NULL;

  if (!private_key->SetInteger(L"size", size()))
    return NULL;

  Value* public_key_value = public_key()->GetValue();
  if (public_key_value == NULL)
    return NULL;

  if (!private_key->Set(L"publicKey", public_key_value))
    return NULL;

  return private_key.release();
}

const KeyType* DSAPrivateKey::GetType() const {
  static const KeyType* key_type = KeyType::Create("DSA_PRIV");
  return key_type;
}

bool DSAPrivateKey::Sign(const std::string& data,
                         std::string* signature) const {
  if (dsa_impl() == NULL || signature == NULL)
    return false;

  MessageDigestImpl* digest_impl = CryptoFactory::SHA1();
  if (digest_impl == NULL)
    return false;

  std::string message_digest;
  if (!digest_impl->Digest(data, &message_digest))
    return false;

  return dsa_impl()->Sign(message_digest, signature);
}

}  // namespace keyczar
