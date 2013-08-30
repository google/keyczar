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
#include <keyczar/ecdsa_public_key.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/values.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/ecdsa_impl.h>
#include <keyczar/key_type.h>
#include <keyczar/key_util.h>
#include <keyczar/message_digest_impl.h>

namespace keyczar {

// static
ECDSAPublicKey* ECDSAPublicKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* public_key = static_cast<const DictionaryValue*>(
      &root_key);

  ECDSAImpl::ECDSAIntermediateKey intermediate_key;

  if (!util::DeserializeString(*public_key, "publicBytes",
                               &intermediate_key.public_key))
    return NULL;

  std::string named_curve;
  if (!public_key->GetString("namedCurve", &named_curve))
    return NULL;
  intermediate_key.curve = ECDSAImpl::GetCurve(named_curve);
  if (intermediate_key.curve == ECDSAImpl::UNDEF) {
    LOG(ERROR) << "Invalid curve " << named_curve;
    return NULL;
  }

  scoped_ptr<ECDSAImpl> ecdsa_public_key_impl(
      CryptoFactory::CreatePublicECDSA(intermediate_key));
  if (ecdsa_public_key_impl.get() == NULL)
    return NULL;

  // Check the size is valid.
  int size = ECDSAImpl::GetSizeFromCurve(intermediate_key.curve);
  if (!KeyType::IsValidCipherSize(KeyType::ECDSA_PUB, size))
    return NULL;

  return new ECDSAPublicKey(ecdsa_public_key_impl.release(), size);
}

Value* ECDSAPublicKey::GetValue() const {
  scoped_ptr<DictionaryValue> public_key(new DictionaryValue);
  if (public_key.get() == NULL)
    return NULL;

  ECDSAImpl::ECDSAIntermediateKey intermediate_key;
  if (!ecdsa_impl()->GetPublicAttributes(&intermediate_key))
    return NULL;

  if (!util::SerializeString(intermediate_key.public_key, "publicBytes",
                             public_key.get()))
    return NULL;

  if (!public_key->SetString("namedCurve",
                             ECDSAImpl::GetCurveName(intermediate_key.curve)))
    return NULL;

  return public_key.release();
}

bool ECDSAPublicKey::Hash(std::string* hash) const {
  if (hash == NULL)
    return false;

  ECDSAImpl::ECDSAIntermediateKey key;
  if (!ecdsa_impl()->GetPublicAttributes(&key))
    return false;

  // Builds a message digest based on public attributes
  scoped_ptr<MessageDigestImpl> digest_impl(CryptoFactory::SHA1());
  if (digest_impl.get() == NULL)
    return false;

  digest_impl->Init();
  AddToHash(key.public_key, *digest_impl);
  AddToHash(ECDSAImpl::GetCurveName(key.curve), *digest_impl);
  std::string full_hash;
  digest_impl->Final(&full_hash);
  CHECK_LE(Key::GetHashSize(), static_cast<int>(full_hash.length()));

  base::Base64WEncode(full_hash.substr(0, Key::GetHashSize()), hash);
  return true;
}

bool ECDSAPublicKey::Verify(const std::string& data,
                            const std::string& signature) const {
  if (ecdsa_impl() == NULL)
    return false;

  scoped_ptr<MessageDigestImpl> digest_impl(CryptoFactory::SHAFromECCSize(size()));
  if (digest_impl.get() == NULL)
    return false;

  std::string message_digest;
  if (!digest_impl->Digest(data, &message_digest))
    return false;

  // The hash is truncated to the key size.
  const uint32 byte_size = size() / 8;
  if (message_digest.length() > byte_size)
    message_digest = message_digest.substr(0, byte_size);

  return ecdsa_impl()->Verify(message_digest, signature);
}

}  // namespace keyczar
