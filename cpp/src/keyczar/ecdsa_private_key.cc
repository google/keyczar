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
#include "keyczar/ecdsa_private_key.h"

#include "base/logging.h"
#include "base/values.h"

#include "keyczar/crypto_factory.h"
#include "keyczar/key_type.h"
#include "keyczar/key_util.h"

namespace keyczar {

// static
ECDSAPrivateKey* ECDSAPrivateKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* private_key = static_cast<const DictionaryValue*>(
      &root_key);

  ECDSAImpl::ECDSAIntermediateKey intermediate_key;

  // private_key
  if (!util::DeserializeString(*private_key, L"privateKey",
                               &intermediate_key.private_key))
    return NULL;

  // named_curve
  std::string named_curve;
  if (!private_key->GetString(L"namedCurve", &named_curve))
    return NULL;
  intermediate_key.curve = ECDSAImpl::GetCurve(named_curve);
  if (intermediate_key.curve == ECDSAImpl::UNDEF) {
    LOG(ERROR) << "Invalid curve " << named_curve;
    return NULL;
  }

  DictionaryValue* public_key = NULL;
  if (!private_key->GetDictionary(L"publicKey", &public_key))
    return NULL;

  if (public_key == NULL)
    return NULL;

  if (!util::DeserializeString(*public_key, L"publicBytes",
                               &intermediate_key.public_key))
    return NULL;

  scoped_ptr<ECDSAImpl> ecdsa_private_key_impl(
      CryptoFactory::CreatePrivateECDSA(intermediate_key));
  if (ecdsa_private_key_impl.get() == NULL)
    return NULL;

  // Check the size is valid.
  int size = ECDSAImpl::GetSizeFromCurve(intermediate_key.curve);
  if (!IsValidSize("ECDSA_PRIV", size))
    return NULL;

  scoped_ptr<ECDSAImpl> ecdsa_public_key_impl(
      CryptoFactory::CreatePublicECDSA(intermediate_key));
  if (ecdsa_public_key_impl.get() == NULL)
    return NULL;

  ECDSAPublicKey* ecdsa_public_key = new ECDSAPublicKey(
      ecdsa_public_key_impl.release(), size);
  if (ecdsa_public_key == NULL)
    return NULL;

  return new ECDSAPrivateKey(ecdsa_private_key_impl.release(),
                             ecdsa_public_key,
                             size);
}

// static
ECDSAPrivateKey* ECDSAPrivateKey::GenerateKey(int size) {
  if (!IsValidSize("ECDSA_PRIV", size))
    return NULL;

  ECDSAImpl::Curve curve = ECDSAImpl::GetCurveFromSize(size);
  if (curve == ECDSAImpl::UNDEF) {
    LOG(ERROR) << "Unsupported size " << size;
    return NULL;
  }

  scoped_ptr<ECDSAImpl> ecdsa_private_key_impl(
      CryptoFactory::GeneratePrivateECDSA(curve));
  if (ecdsa_private_key_impl.get() == NULL)
    return NULL;

  ECDSAImpl::ECDSAIntermediateKey intermediate_public_key;
  ecdsa_private_key_impl->GetPublicAttributes(&intermediate_public_key);

  scoped_ptr<ECDSAImpl> ecdsa_public_key_impl(
      CryptoFactory::CreatePublicECDSA(intermediate_public_key));
  if (ecdsa_public_key_impl.get() == NULL)
    return NULL;

  ECDSAPublicKey* ecdsa_public_key = new ECDSAPublicKey(
      ecdsa_public_key_impl.release(), size);
  if (ecdsa_public_key == NULL)
    return NULL;

  return new ECDSAPrivateKey(ecdsa_private_key_impl.release(),
                             ecdsa_public_key,
                             size);
}

// static
ECDSAPrivateKey* ECDSAPrivateKey::CreateFromPEMKey(
    const std::string& filename, const std::string* passphrase) {
  scoped_ptr<ECDSAImpl> ecdsa_private_key_impl(
      CryptoFactory::CreatePrivateECDSAFromPEMKey(filename, passphrase));
  if (ecdsa_private_key_impl.get() == NULL)
    return NULL;

  ECDSAImpl::ECDSAIntermediateKey intermediate_public_key;
  ecdsa_private_key_impl->GetPublicAttributes(&intermediate_public_key);

  int size = ECDSAImpl::GetSizeFromCurve(intermediate_public_key.curve);
  if (!IsValidSize("ECDSA_PRIV", size))
    return NULL;

  scoped_ptr<ECDSAImpl> ecdsa_public_key_impl(
      CryptoFactory::CreatePublicECDSA(intermediate_public_key));
  if (ecdsa_public_key_impl.get() == NULL)
    return NULL;

  ECDSAPublicKey* ecdsa_public_key = new ECDSAPublicKey(
      ecdsa_public_key_impl.release(), size);
  if (ecdsa_public_key == NULL)
    return NULL;

  return new ECDSAPrivateKey(ecdsa_private_key_impl.release(),
                             ecdsa_public_key,
                             size);
}

Value* ECDSAPrivateKey::GetValue() const {
  scoped_ptr<DictionaryValue> private_key(new DictionaryValue);
  if (private_key.get() == NULL)
    return NULL;

  ECDSAImpl::ECDSAIntermediateKey intermediate_key;
  if (!ecdsa_impl()->GetAttributes(&intermediate_key))
    return NULL;

  if (!util::SerializeString(intermediate_key.private_key, L"privateKey",
                             private_key.get()))
    return NULL;

  if (!private_key->SetString(L"namedCurve",
                              ECDSAImpl::GetCurveName(intermediate_key.curve)))
    return NULL;

  Value* public_key_value = public_key()->GetValue();
  if (public_key_value == NULL)
    return NULL;

  if (!private_key->Set(L"publicKey", public_key_value))
    return NULL;

  return private_key.release();
}

bool ECDSAPrivateKey::Sign(const std::string& data,
                           std::string* signature) const {
  if (ecdsa_impl() == NULL || signature == NULL)
    return false;

  MessageDigestImpl* digest_impl = CryptoFactory::SHAFromECCSize(size());
  if (digest_impl == NULL)
    return false;

  std::string message_digest;
  if (!digest_impl->Digest(data, &message_digest))
    return false;

  // The hash is truncated to the key size.
  if (message_digest.length() > size() / 8)
    message_digest = message_digest.substr(0, size() / 8);

  return ecdsa_impl()->Sign(message_digest, signature);
}

}  // namespace keyczar
