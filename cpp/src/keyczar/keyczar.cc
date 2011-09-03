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
#include <keyczar/keyczar.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/base/values.h>
#include <keyczar/base/zlib.h>
#include <keyczar/key.h>
#include <keyczar/keyset_metadata.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/util.h>

namespace keyczar {

bool Keyczar::Sign(const std::string& data, std::string* signature) const {
  return false;
}

std::string Keyczar::Sign(const std::string& data) const {
  return "";
}

bool Keyczar::AttachedSign(const std::string& data,
                                  const std::string& hidden,
                                  std::string* signed_data) const {
  return false;
}

std::string Keyczar::AttachedSign(const std::string& data,
                                  const std::string& hidden) const {
  std::string signed_data;
  if (AttachedSign(data, hidden, &signed_data))
    return signed_data;
  else
    return "";
}

bool Keyczar::Verify(const std::string& data,
                     const std::string& signature) const {
  return false;
}

bool Keyczar::AttachedVerify(const std::string& signed_blob,
                             const std::string& hidden,
                             std::string* blob) const {
  return false;
}

bool Keyczar::GetAttachedWithoutVerify(const std::string& signed_blob,
                                       std::string* blob) const {
  return false;
}

bool Keyczar::Encrypt(const std::string& plaintext,
                      std::string* ciphertext) const {
  return false;
}

std::string Keyczar::Encrypt(const std::string& plaintext) const {
  return "";
}

bool Keyczar::Decrypt(const std::string& ciphertext,
                      std::string* plaintext) const {
  return false;
}

std::string Keyczar::Decrypt(const std::string& ciphertext) const {
  return "";
}

KeyPurpose::Type Keyczar::GetKeyPurpose() const {
  if (keyset() == NULL)
    return KeyPurpose::UNDEF;

  const KeysetMetadata* meta = keyset()->metadata();
  if (meta == NULL)
    return KeyPurpose::UNDEF;

  return meta->key_purpose();
}

KeyType::Type Keyczar::GetKeyType() const {
  if (keyset() == NULL)
    return KeyType::UNDEF;

  const KeysetMetadata* meta = keyset()->metadata();
  if (meta == NULL)
    return KeyType::UNDEF;

  return meta->key_type();
}

bool Keyczar::GetHash(const std::string& bytes, std::string* hash) const {
  if (hash == NULL)
    return false;

  if (static_cast<int>(bytes.length()) < Key::GetHeaderSize())
    return false;

  if (!base::Base64WEncode(bytes.substr(1, Key::GetHashSize()), hash))
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
      return base::Base64WEncode(input_value, encoded_value);
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
      return base::Base64WDecode(encoded_value, decoded_value);
    default:
      NOTREACHED();
  }
  return false;
}

bool Keyczar::Compress(const std::string& input,
                       std::string* output) const {
  if (output == NULL)
    return false;

  const Compression comp = compression();
  switch (comp) {
    case NO_COMPRESSION:
      output->assign(input);
      return true;
#if HAVE_ZLIB
    case GZIP:
      return base::Zlib::Compress(base::Zlib::GZIP, input, output);
    case ZLIB:
      return base::Zlib::Compress(base::Zlib::ZLIB, input, output);
#endif  // HAVE_ZLIB
    default:
      LOG(ERROR) << "Unsupported compression format (" << comp << ")";
  }
  return false;
}

bool Keyczar::Decompress(const std::string& input,
                         std::string* output) const {
  if (output == NULL)
    return false;

  const Compression comp = compression();
  switch (comp) {
    case NO_COMPRESSION:
      output->assign(input);
      return true;
#if HAVE_ZLIB
    case GZIP:
      return base::Zlib::Decompress(base::Zlib::GZIP, input, output);
    case ZLIB:
      return base::Zlib::Decompress(base::Zlib::ZLIB, input, output);
#endif  // HAVE_ZLIB
    default:
      LOG(ERROR) << "Unsupported compression format (" << comp << ")";
  }
  return false;
}

const Key* Keyczar::LookupKey(const std::string& key_header) const {
  if (keyset() == NULL)
    return NULL;

  std::string hash;
  if (!GetHash(key_header, &hash))
    return NULL;

  return keyset()->GetKeyFromHash(hash);
}

// Note: |returnType| is for type inference.  It's value is ignored.
template <class T>
static T* ReadKeyset(const rw::KeysetReader& reader,
                     T* returnType) {
  scoped_ptr<Keyset> keyset(Keyset::Read(reader, true));
  if (keyset.get() == NULL)
    return NULL;

  scoped_ptr<T> keyczar(new T(keyset.release()));
  if (keyczar.get() == NULL)
    return NULL;

  if (!keyczar->IsAcceptablePurpose())
    return NULL;

  return keyczar.release();
}

// Note: |returnType| is for type inference.  It's value is ignored.
template<class T>
static T* ReadKeyset(const FilePath& location,
                     T* returnType) {
  const scoped_ptr<rw::KeysetReader> reader(
      rw::KeysetReader::CreateReader(location));
  if (reader.get() == NULL)
    return NULL;
  return ReadKeyset(*reader, returnType);
}

// Note: |returnType| is for type inference.  It's value is ignored.
template<class T>
static T* ReadKeyset(const std::string& location,
                     T* returnType) {
  return ReadKeyset(FilePath(location), returnType);
}

// static
Encrypter* Encrypter::Read(const std::string& location) {
  return ReadKeyset(location, (Encrypter*)0);
}

// static
Encrypter* Encrypter::Read(const FilePath& location) {
  return ReadKeyset(location, (Encrypter*)0);
}

// static
Encrypter* Encrypter::Read(const rw::KeysetReader& reader) {
  return ReadKeyset(reader, (Encrypter*)0);
}

bool Encrypter::Encrypt(const std::string& plaintext,
                        std::string* ciphertext) const {
  if (keyset() == NULL)
    return false;

  const Key* key = keyset()->primary_key();
  if (key == NULL)
    return false;

  std::string compressed_plaintext;
  if (!Compress(plaintext, &compressed_plaintext))
    return false;

  std::string ciphertext_bytes;
  if (!key->Encrypt(compressed_plaintext, &ciphertext_bytes))
    return false;

  if (!Encode(ciphertext_bytes, ciphertext))
    return false;

  return true;
}

std::string Encrypter::Encrypt(const std::string& plaintext) const {
  std::string ciphertext;
  if (!Encrypt(plaintext, &ciphertext))
    return "";
  return ciphertext;
}

bool Encrypter::IsAcceptablePurpose() const {
  const KeyPurpose::Type purpose = GetKeyPurpose();
  return purpose == KeyPurpose::ENCRYPT ||
      purpose == KeyPurpose::DECRYPT_AND_ENCRYPT;
}

// static
Crypter* Crypter::Read(const std::string& location) {
  return ReadKeyset(location, (Crypter*)0);
}

// static
Crypter* Crypter::Read(const FilePath& location) {
  return ReadKeyset(location, (Crypter*)0);
}

// static
Crypter* Crypter::Read(const rw::KeysetReader& reader) {
  return ReadKeyset(reader, (Crypter*)0);
}

bool Crypter::Decrypt(const std::string& ciphertext,
                      std::string* plaintext) const {
  if (keyset() == NULL || plaintext == NULL)
    return false;

  std::string ciphertext_bytes;
  if (!Decode(ciphertext, &ciphertext_bytes))
    return false;

  std::string compressed_plaintext;
  const Key* key = LookupKey(ciphertext_bytes);
  if (key == NULL || !key->Decrypt(ciphertext_bytes, &compressed_plaintext))
    return false;

  return Decompress(compressed_plaintext, plaintext);
}

std::string Crypter::Decrypt(const std::string& ciphertext) const {
  std::string plaintext;
  if (!Decrypt(ciphertext, &plaintext))
    return "";
  return plaintext;
}

bool Crypter::IsAcceptablePurpose() const {
  return GetKeyPurpose() == KeyPurpose::DECRYPT_AND_ENCRYPT;
}

// static
Verifier* Verifier::Read(const std::string& location) {
  return ReadKeyset(location, (Verifier*)0);
}

// static
Verifier* Verifier::Read(const FilePath& location) {
  return ReadKeyset(location, (Verifier*)0);
}

// static
Verifier* Verifier::Read(const rw::KeysetReader& reader) {
  return ReadKeyset(reader, (Verifier*)0);
}

bool Verifier::Verify(const std::string& data,
                      const std::string& signature) const {
  std::string signature_bytes;
  return Decode(signature, &signature_bytes)
      && InternalVerify(BuildMessageToSign(data, NULL), signature_bytes,
                        signature_bytes.substr(Key::GetHeaderSize()));
}

bool Verifier::AttachedVerify(const std::string& signed_data,
                              const std::string& hidden,
                              std::string* data) const {
  std::string signature;
  std::string header;
  return data != NULL
      && ParseAttachedSignature(signed_data, &header, data, &signature)
      && InternalVerify(BuildMessageToSign(*data, &hidden), header, signature);
}

bool Verifier::IsAcceptablePurpose() const {
  const KeyPurpose::Type purpose = GetKeyPurpose();
  return purpose == KeyPurpose::VERIFY ||
      purpose == KeyPurpose::SIGN_AND_VERIFY;
}

std::string Verifier::BuildMessageToSign(const std::string& data,
                                         const std::string* hidden) const {
  std::string message(data);
  if (hidden) {
    message.append(util::Int32ToByteString(hidden->size()));
    message.append(*hidden);
  }
  message.push_back(Key::GetVersionByte());
  return message;
}

bool Verifier::InternalVerify(const std::string& verification_data,
                              const std::string& key_header,
                              const std::string& signature) const {
  const Key* key = LookupKey(key_header);
  return key != NULL && key->Verify(verification_data, signature);
}

bool Verifier::ParseAttachedSignature(const std::string& signed_data,
                                      std::string* header,
                                      std::string* data,
                                      std::string* signature) const {
  std::string decoded_bytes;
  if (!Decode(signed_data, &decoded_bytes))
    return false;

  if (header != NULL)
    *header = decoded_bytes.substr(0, Key::GetHeaderSize());

  int cur_offset = Key::GetHeaderSize();
  int data_len;
  if (!util::ByteStringToInt32(decoded_bytes, cur_offset, &data_len))
    return false;

  cur_offset += sizeof(data_len);
  if (decoded_bytes.size() < cur_offset + data_len)
    return false;

  if (data != NULL)
    *data = decoded_bytes.substr(cur_offset, data_len);

  cur_offset += data_len;
  if (signature != NULL)
    *signature = decoded_bytes.substr(cur_offset);

  return true;
}

// static
UnversionedVerifier* UnversionedVerifier::Read(const std::string& location) {
  return ReadKeyset(location, (UnversionedVerifier*)0);
}

// static
UnversionedVerifier* UnversionedVerifier::Read(const FilePath& location) {
  return ReadKeyset(location, (UnversionedVerifier*)0);
}

// static
UnversionedVerifier* UnversionedVerifier::Read(const rw::KeysetReader& reader) {
  return ReadKeyset(reader, (UnversionedVerifier*)0);
}

bool UnversionedVerifier::Verify(const std::string& data,
                                 const std::string& signature) const {
  if (keyset() == NULL)
    return false;

  std::string signature_bytes;
  if (!Decode(signature, &signature_bytes))
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
  const KeyPurpose::Type purpose = GetKeyPurpose();
  return purpose == KeyPurpose::VERIFY ||
      purpose == KeyPurpose::SIGN_AND_VERIFY;
}

// static
Signer* Signer::Read(const std::string& location) {
  return ReadKeyset(location, (Signer*)0);
}

// static
Signer* Signer::Read(const FilePath& location) {
  return ReadKeyset(location, (Signer*)0);
}

// static
Signer* Signer::Read(const rw::KeysetReader& reader) {
  return ReadKeyset(reader, (Signer*)0);
}

bool Signer::Sign(const std::string& data, std::string* signature) const {
  std::string raw_signature;
  std::string key_header;
  if (!InternalSign(data, NULL /* hidden */, &raw_signature, &key_header))
    return false;
  return Encode(key_header + raw_signature, signature);
}

std::string Signer::Sign(const std::string& data) const {
  std::string signature;
  if (!Sign(data, &signature))
    return "";
  return signature;
}

bool Signer::AttachedSign(const std::string& data,
                          const std::string& hidden,
                          std::string* signed_data) const {
  std::string signature_bytes;
  std::string key_header;
  if (!InternalSign(data, &hidden, &signature_bytes, &key_header))
    return false;

  std::string unencoded_result(key_header);
  unencoded_result.append(util::Int32ToByteString(data.size()));
  unencoded_result.append(data);
  unencoded_result.append(signature_bytes);

  return Encode(unencoded_result, signed_data);
}

bool Signer::IsAcceptablePurpose() const {
  const KeyPurpose::Type purpose = GetKeyPurpose();
  return purpose == KeyPurpose::SIGN_AND_VERIFY;
}

bool Signer::InternalSign(const std::string& data,
                          const std::string* hidden,
                          std::string* signature,
                          std::string* key_header) const {
  if (keyset() == NULL || signature == NULL)
    return false;

  const Key* key = keyset()->primary_key();
  return key != NULL
      && key->Header(key_header)
      && key->Sign(BuildMessageToSign(data, hidden), signature);
}

// static
UnversionedSigner* UnversionedSigner::Read(const std::string& location) {
  return ReadKeyset(location, (UnversionedSigner*)0);
}

// static
UnversionedSigner* UnversionedSigner::Read(const FilePath& location) {
  return ReadKeyset(location, (UnversionedSigner*)0);
}

// static
UnversionedSigner* UnversionedSigner::Read(const rw::KeysetReader& reader) {
  return ReadKeyset(reader, (UnversionedSigner*)0);
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
  if (!Sign(data, &signature))
    return "";
  return signature;
}

bool UnversionedSigner::IsAcceptablePurpose() const {
  return GetKeyPurpose() == KeyPurpose::SIGN_AND_VERIFY;
}

}  // namespace keyczar
