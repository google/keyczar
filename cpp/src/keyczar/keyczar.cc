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
#include "keyczar/keyczar.h"

#include "base/base64w.h"
#include "base/file_path.h"

#include "keyczar/key.h"
#include "keyczar/key_purpose.h"
#include "keyczar/keyset_file_reader.h"
#include "keyczar/keyset_metadata.h"

namespace keyczar {

bool Keyczar::Sign(const std::string& data, std::string* signature) const {
  return false;
}

std::string Keyczar::Sign(const std::string& data) const {
  return "";
}

bool Keyczar::Verify(const std::string& data,
                     const std::string& signature) const {
  return false;
}

bool Keyczar::Encrypt(const std::string& data, std::string* ciphertext) const {
  return false;
}

std::string Keyczar::Encrypt(const std::string& data) const {
  return "";
}

bool Keyczar::Decrypt(const std::string& ciphertext, std::string* data) const {
  return false;
}

std::string Keyczar::Decrypt(const std::string& ciphertext) const {
  return "";
}

const KeyPurpose* Keyczar::GetKeyPurpose() const {
  if (keyset() == NULL)
    return NULL;

  const KeysetMetadata* meta = keyset()->metadata();
  if (meta == NULL)
    return NULL;

  return meta->key_purpose();
}

bool Keyczar::GetHash(const std::string& bytes, std::string* hash) const {
  if (hash == NULL)
    return false;

  if (static_cast<int>(bytes.length()) < Key::GetHeaderSize())
    return false;

  if (!Base64WEncode(bytes.substr(1, Key::GetHashSize()), hash))
    return false;

  return true;
}

bool Keyczar::Encode(const std::string& input_value,
                     std::string* encoded_value) const {
  if (encoded_value == NULL)
    return false;

  const Encoding enc = encoding();
  switch (enc) {
    case NO_ENCODING:
      encoded_value->assign(input_value);
      return true;
    case BASE64W:
      return Base64WEncode(input_value, encoded_value);
    default:
      NOTREACHED();
  }
  return false;
}

bool Keyczar::Decode(const std::string& encoded_value,
                     std::string* decoded_value) const {
  if (decoded_value == NULL)
    return false;

  const Encoding enc = encoding();
  switch (enc) {
    case NO_ENCODING:
      decoded_value->assign(encoded_value);
      return true;
    case BASE64W:
      return Base64WDecode(encoded_value, decoded_value);
    default:
      NOTREACHED();
  }
  return false;
}

// static
Encrypter* Encrypter::Read(const std::string& location) {
  const KeysetFileReader reader(location);
  return Encrypter::Read(reader);
}

// static
Encrypter* Encrypter::Read(const FilePath& location) {
  const KeysetFileReader reader(location);
  return Encrypter::Read(reader);
}

// static
Encrypter* Encrypter::Read(const KeysetReader& reader) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<Encrypter> encrypter(new Encrypter(keyset.release()));
  if (encrypter.get() == NULL)
    return NULL;

  if (!encrypter->IsAcceptablePurpose())
    return NULL;

  return encrypter.release();
}

bool Encrypter::Encrypt(const std::string& data,
                        std::string* ciphertext) const {
  if (keyset() == NULL)
    return false;

  const Key* key = keyset()->primary_key();
  if (key == NULL)
    return false;

  std::string ciphertext_bytes;
  if (!key->Encrypt(data, &ciphertext_bytes))
    return false;

  if (!Encode(ciphertext_bytes, ciphertext))
    return false;

  return true;
}

std::string Encrypter::Encrypt(const std::string& data) const {
  std::string ciphertext;
  bool result = Encrypt(data, &ciphertext);
  if (!result)
    return "";
  return ciphertext;
}

bool Encrypter::IsAcceptablePurpose() const {
  const KeyPurpose* purpose = GetKeyPurpose();
  if (purpose == NULL)
    return false;

  return purpose->type() == KeyPurpose::ENCRYPT ||
      purpose->type() == KeyPurpose::DECRYPT_AND_ENCRYPT;
}

// static
Crypter* Crypter::Read(const std::string& location) {
  const KeysetFileReader reader(location);
  return Crypter::Read(reader);
}

// static
Crypter* Crypter::Read(const FilePath& location) {
  const KeysetFileReader reader(location);
  return Crypter::Read(reader);
}

// static
Crypter* Crypter::Read(const KeysetReader& reader) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<Crypter> crypter(new Crypter(keyset.release()));
  if (crypter.get() == NULL)
    return NULL;

  if (!crypter->IsAcceptablePurpose())
    return NULL;

  return crypter.release();
}

bool Crypter::Decrypt(const std::string& ciphertext, std::string* data) const {
  if (keyset() == NULL)
    return false;

  std::string ciphertext_bytes;
  if (!Decode(ciphertext, &ciphertext_bytes))
    return false;

  std::string hash;
  if (!GetHash(ciphertext_bytes, &hash))
    return false;

  const Key* key = keyset()->GetKeyFromHash(hash);
  if (key == NULL)
    return false;

  if (!key->Decrypt(ciphertext_bytes, data))
    return false;

  return true;
}

std::string Crypter::Decrypt(const std::string& ciphertext) const {
  std::string plaintext;
  bool result = Decrypt(ciphertext, &plaintext);
  if (!result)
    return "";
  return plaintext;
}

bool Crypter::IsAcceptablePurpose() const {
  const KeyPurpose* purpose = GetKeyPurpose();
  if (purpose == NULL)
    return false;

  return purpose->type() == KeyPurpose::DECRYPT_AND_ENCRYPT;
}

// static
Verifier* Verifier::Read(const std::string& location) {
  const KeysetFileReader reader(location);
  return Verifier::Read(reader);
}

// static
Verifier* Verifier::Read(const FilePath& location) {
  const KeysetFileReader reader(location);
  return Verifier::Read(reader);
}

// static
Verifier* Verifier::Read(const KeysetReader& reader) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<Verifier> verifier(new Verifier(keyset.release()));
  if (verifier.get() == NULL)
    return NULL;

  if (!verifier->IsAcceptablePurpose())
    return NULL;

  return verifier.release();
}

bool Verifier::Verify(const std::string& data,
                      const std::string& signature) const {
  if (keyset() == NULL)
    return false;

  std::string signature_bytes;
  if (!Decode(signature, &signature_bytes))
    return false;

  std::string hash;
  if (!GetHash(signature_bytes, &hash))
    return false;

  const Key* key = keyset()->GetKeyFromHash(hash);
  if (key == NULL)
    return false;

  std::string data_copy(data);
  data_copy.push_back(Key::GetVersionByte());
  if (!key->Verify(data_copy, signature_bytes.substr(Key::GetHeaderSize())))
    return false;

  return true;
}

bool Verifier::IsAcceptablePurpose() const {
  const KeyPurpose* purpose = GetKeyPurpose();
  if (purpose == NULL)
    return false;

  return purpose->type() == KeyPurpose::VERIFY ||
      purpose->type() == KeyPurpose::SIGN_AND_VERIFY;
}

// static
UnversionedVerifier* UnversionedVerifier::Read(const std::string& location) {
  const KeysetFileReader reader(location);
  return UnversionedVerifier::Read(reader);
}

// static
UnversionedVerifier* UnversionedVerifier::Read(const FilePath& location) {
  const KeysetFileReader reader(location);
  return UnversionedVerifier::Read(reader);
}

// static
UnversionedVerifier* UnversionedVerifier::Read(const KeysetReader& reader) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<UnversionedVerifier> verifier(new UnversionedVerifier(
                                               keyset.release()));
  if (verifier.get() == NULL)
    return NULL;

  if (!verifier->IsAcceptablePurpose())
    return NULL;

  return verifier.release();
}

bool UnversionedVerifier::Verify(const std::string& data,
                                 const std::string& signature) const {
  if (keyset() == NULL)
    return false;

  std::string signature_bytes;
  if (!Decode(signature, &signature_bytes))
    return false;

  std::string hash;
  if (!GetHash(signature_bytes, &hash))
    return false;

  Keyset::const_iterator key_iterator = keyset()->Begin();
  for (; key_iterator != keyset()->End(); ++key_iterator) {
    const Key* key = key_iterator->second;
    if (key == NULL)
      return false;

    if (key->Verify(data, signature_bytes))
      return true;
  }

  return false;
}

bool UnversionedVerifier::IsAcceptablePurpose() const {
  const KeyPurpose* purpose = GetKeyPurpose();
  if (purpose == NULL)
    return false;

  return purpose->type() == KeyPurpose::VERIFY ||
      purpose->type() == KeyPurpose::SIGN_AND_VERIFY;
}

// static
Signer* Signer::Read(const std::string& location) {
  const KeysetFileReader reader(location);
  return Signer::Read(reader);
}

// static
Signer* Signer::Read(const FilePath& location) {
  const KeysetFileReader reader(location);
  return Signer::Read(reader);
}

// static
Signer* Signer::Read(const KeysetReader& reader) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<Signer> signer(new Signer(keyset.release()));
  if (signer.get() == NULL)
    return NULL;

  if (!signer->IsAcceptablePurpose())
    return NULL;

  return signer.release();
}

bool Signer::Sign(const std::string& data, std::string* signature) const {
  if (keyset() == NULL)
    return false;

  const Key* key = keyset()->primary_key();
  if (key == NULL)
    return false;

  std::string data_copy(data);
  data_copy.push_back(Key::GetVersionByte());

  std::string signed_bytes;
  if (!key->Sign(data_copy, &signed_bytes))
    return false;

  std::string header;
  if (!key->Header(&header))
    return false;

  std::string message(header);
  message.append(signed_bytes);

  if (!Encode(message, signature))
    return false;

  return true;
}

std::string Signer::Sign(const std::string& data) const {
  std::string signature;
  bool result = Sign(data, &signature);
  if (!result)
    return "";
  return signature;
}

bool Signer::IsAcceptablePurpose() const {
  const KeyPurpose* purpose = GetKeyPurpose();
  if (purpose == NULL)
    return false;

  return purpose->type() == KeyPurpose::SIGN_AND_VERIFY;
}

// static
UnversionedSigner* UnversionedSigner::Read(const std::string& location) {
  const KeysetFileReader reader(location);
  return UnversionedSigner::Read(reader);
}

// static
UnversionedSigner* UnversionedSigner::Read(const FilePath& location) {
  const KeysetFileReader reader(location);
  return UnversionedSigner::Read(reader);
}

// static
UnversionedSigner* UnversionedSigner::Read(const KeysetReader& reader) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<UnversionedSigner> signer(new UnversionedSigner(keyset.release()));
  if (signer.get() == NULL)
    return NULL;

  if (!signer->IsAcceptablePurpose())
    return NULL;

  return signer.release();
}

bool UnversionedSigner::Sign(const std::string& data,
                             std::string* signature) const {
  if (keyset() == NULL)
    return false;

  const Key* key = keyset()->primary_key();
  if (key == NULL)
    return false;

  std::string signed_bytes;
  if (!key->Sign(data, &signed_bytes))
    return false;

  if (!Encode(signed_bytes, signature))
    return false;

  return true;
}

std::string UnversionedSigner::Sign(const std::string& data) const {
  std::string signature;
  bool result = Sign(data, &signature);
  if (!result)
    return "";
  return signature;
}

bool UnversionedSigner::IsAcceptablePurpose() const {
  const KeyPurpose* purpose = GetKeyPurpose();
  if (purpose == NULL)
    return false;

  return purpose->type() == KeyPurpose::SIGN_AND_VERIFY;
}

}  // namespace keyczar
