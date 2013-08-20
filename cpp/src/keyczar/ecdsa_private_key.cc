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
#include <keyczar/ecdsa_private_key.h>

#include <keyczar/base/logging.h>
#include <keyczar/base/values.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/key_type.h>
#include <keyczar/key_util.h>

namespace keyczar {

// static
ECDSAPrivateKey* ECDSAPrivateKey::CreateFromValue(const Value& root_key) {
  if (!root_key.IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* private_key = static_cast<const DictionaryValue*>(
      &root_key);

  ECDSAImpl::ECDSAIntermediateKey intermediate_key;

  // private_key
  if (!util::SafeDeserializeString(*private_key, "privateKey",
                                   &intermediate_key.private_key))
    return NULL;

  // named_curve
  std::string named_curve;
  if (!private_key->GetString("namedCurve", &named_curve))
    return NULL;
  intermediate_key.curve = ECDSAImpl::GetCurve(named_curve);
  if (intermediate_key.curve == ECDSAImpl::UNDEF) {
    LOG(ERROR) << "Invalid curve " << named_curve;
    return NULL;
  }

  DictionaryValue* public_key = NULL;
  if (!private_key->GetDictionary("publicKey", &public_key))
    return NULL;

  if (public_key == NULL)
    return NULL;

  if (!util::DeserializeString(*public_key, "publicBytes",
                               &intermediate_key.public_key))
    return NULL;

  scoped_ptr<ECDSAImpl> ecdsa_private_key_impl(
      CryptoFactory::CreatePrivateECDSA(intermediate_key));
  if (ecdsa_private_key_impl.get() == NULL)
    return NULL;

  // Check the size is valid.
  int size = ECDSAImpl::GetSizeFromCurve(intermediate_key.curve);
  if (!KeyType::IsValidCipherSize(KeyType::ECDSA_PRIV, size))
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
  if (!KeyType::IsValidCipherSize(KeyType::ECDSA_PRIV, size))
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
  if (!ecdsa_private_key_impl->GetPublicAttributes(&intermediate_public_key))
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

// static
ECDSAPrivateKey* ECDSAPrivateKey::CreateFromPEMPrivateKey(
    const std::string& filename, const std::string* passphrase) {
  scoped_ptr<ECDSAImpl> ecdsa_private_key_impl(
      CryptoFactory::CreatePrivateECDSAFromPEMPrivateKey(filename, passphrase));
  if (ecdsa_private_key_impl.get() == NULL)
    return NULL;

  ECDSAImpl::ECDSAIntermediateKey intermediate_public_key;
  if (!ecdsa_private_key_impl->GetPublicAttributes(&intermediate_public_key))
    return NULL;

  int size = ECDSAImpl::GetSizeFromCurve(intermediate_public_key.curve);
  if (!KeyType::IsValidCipherSize(KeyType::ECDSA_PRIV, size))
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

  if (!util::SafeSerializeString(intermediate_key.private_key, "privateKey",
                                 private_key.get()))
    return NULL;

  if (!private_key->SetString("namedCurve",
                              ECDSAImpl::GetCurveName(intermediate_key.curve)))
    return NULL;

  Value* public_key_value = public_key()->GetValue();
  if (public_key_value == NULL)
    return NULL;

  if (!private_key->Set("publicKey", public_key_value))
    return NULL;

  return private_key.release();
}

bool ECDSAPrivateKey::ExportPrivateKey(const std::string& filename,
                                       const std::string* passphrase) const {
  if (ecdsa_impl() == NULL)
    return false;
  return ecdsa_impl()->ExportPrivateKey(filename, passphrase);
}

bool ECDSAPrivateKey::Sign(const std::string& data,
                           std::string* signature) const {
  if (ecdsa_impl() == NULL || signature == NULL)
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

  return ecdsa_impl()->Sign(message_digest, signature);
}

}  // namespace keyczar
