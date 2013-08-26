// Copyright 2013 Google Inc.
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
#include <keyczar/interop/operation.h>

#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/session.h>

namespace keyczar {
namespace interop {

// static
Operation * Operation::GetOperationByName(
      const std::string& name, const std::string& key_path,
      const std::string& test_data) {
  if (name == "unversioned") {
    return new UnversionedSignOperation(key_path, test_data);
  } else if (name == "signedSession") {
    return new SignedSessionOperation(key_path, test_data);
  } else if (name == "attached") {
    return new AttachedSignOperation(key_path, test_data);
  } else if (name == "sign") {
    return new SignOperation(key_path, test_data);
  } else if (name == "encrypt") {
    return new EncryptOperation(key_path, test_data);
  } else {
    return NULL;
  }
}

rw::KeysetReader* Operation::GetReader(
    const std::string& algorithm, const std::string& crypter_algorithm,
    const std::string& pub_key) {
  rw::KeysetReader * reader;
  if (crypter_algorithm == "") {
    reader = new rw::KeysetJSONFileReader(GetKeyPath(algorithm + pub_key));
  } else {
    scoped_ptr<keyczar::Crypter> crypter(
        keyczar::Crypter::Read(GetKeyPath(crypter_algorithm)));
    reader = new rw::KeysetEncryptedJSONFileReader(
        GetKeyPath(algorithm + crypter_algorithm + pub_key), crypter.release());
  }
  return reader;
}

bool Operation::OutputToJson(
      const std::string& output, std::string * json_string) {
  std::string encoded_output;
  DictionaryValue dictionary_value;

  if (!base::Base64WEncode(output, &encoded_output)) {
    return false;
  }

  Value * output_value = Value::CreateStringValue(encoded_output);

  if (!dictionary_value.Set("output", output_value)) {
    return false;
  }

  base::JSONWriter::Write(&dictionary_value, false, json_string);

  return true;
}

bool Operation::InputFromJson(
    const DictionaryValue * json_dict, std::string * output) {
  std::string encoded_output;
  if (!json_dict->GetString("output", &encoded_output)) {
    return false;
  }
  if (!base::Base64WDecode(encoded_output, output)) {
    return false;
  }
  return true;
}

const std::string Operation::GetKeyPath(const std::string& algorithm) {
  FilePath fp(key_path_);
  return fp.Append(algorithm).value();
}


bool EncryptOperation::Generate(
    const std::string& algorithm, const DictionaryValue * generate_params,
    std::string * output) {
  keyczar::Keyczar* crypter;
  std::string encoding, crypted_key_set, crypter_class, pub_key;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set) ||
      !generate_params->GetString("class", &crypter_class) ||
      !generate_params->GetString("pubKey", &pub_key)) {
    return false;
  }
  if (crypter_class == "encrypter") {
    crypter = keyczar::Encrypter::Read(
        *GetReader(algorithm, crypted_key_set, ""));
  } else if (crypter_class == "crypter") {
    crypter = keyczar::Crypter::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else {
    return false;
  }
  if (!crypter) return false;
  if (encoding == "unencoded") {
    crypter->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  if (!crypter->Encrypt(test_data_, output)) return false;
  return true;
}

bool EncryptOperation::Test(
      const DictionaryValue * output_json, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params) {
  std::string output;
  if (!InputFromJson(output_json, &output)) return false;
  keyczar::Keyczar* crypter;
  std::string encoding, crypted_key_set, plaintext;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set)) {
    return false;
  }
  crypter = keyczar::Crypter::Read(*GetReader(algorithm, crypted_key_set, ""));

  if (!crypter) return false;
  if (encoding == "unencoded") {
    crypter->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  if (!crypter->Decrypt(output, &plaintext) || plaintext != test_data_) {
    return false;
  }
  return true;
}

bool SignedSessionOperation::OutputToJson(
      const std::string& output, std::string * json_string) {
  // Signed sessions already are in json format
  json_string->assign(std::string(output));
  return true;
}

bool SignedSessionOperation::Generate(
    const std::string& algorithm, const DictionaryValue * generate_params,
    std::string * output) {
  std::string session_material,
      encrypted_data,
      signer_algorithm,
      crypted_key_set,
      pub_key;

  keyczar::Encrypter* key_encrypter;
  keyczar::Signer* signer;

  if (!generate_params->GetString("signer", &signer_algorithm) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set) ||
      !generate_params->GetString("pubKey", &pub_key)) {
    return false;
  }

  key_encrypter = keyczar::Encrypter::Read(
      *GetReader(algorithm, crypted_key_set, pub_key));
  signer = keyczar::Signer::Read(
      *GetReader(signer_algorithm, crypted_key_set, ""));

  if (!key_encrypter || !signer) {
    return false;
  }

  keyczar::SignedSessionEncrypter* crypter =
      SignedSessionEncrypter::NewSessionEncrypter(key_encrypter, signer);

  if (!crypter) {
    return false;
  }
  crypter->set_encoding(Keyczar::NO_ENCODING);
  if (!crypter->EncryptedSessionBlob(&session_material) ||
      !crypter->SessionEncrypt(test_data_, &encrypted_data)) {
    return false;
  }

  std::string encoded_output;
  DictionaryValue dictionary_value;

  if (!base::Base64WEncode(encrypted_data, &encoded_output)) {
    return false;
  }

  Value * output_value = Value::CreateStringValue(encoded_output);
  Value * session_material_value = Value::CreateStringValue(session_material);

  if (!dictionary_value.Set("output", output_value) ||
      !dictionary_value.Set("sessionMaterial", session_material_value)) {
    return false;
  }

  base::JSONWriter::Write(&dictionary_value, false, output);

  return true;
}

bool SignedSessionOperation::Test(
      const DictionaryValue * json_dict, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params) {
  std::string encoded_output,
      signer_algorithm,
      encrypted_data,
      session_material,
      crypted_key_set,
      plaintext;

  if (!json_dict->GetString("output", &encoded_output) ||
      !json_dict->GetString("sessionMaterial", &session_material) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set)) {
    return false;
  }
  if (!base::Base64WDecode(encoded_output, &encrypted_data)) {
    return false;
  }

  keyczar::Crypter* key_decrypter;
  keyczar::Verifier* verifier;

  if (!generate_params->GetString("signer", &signer_algorithm)) {
    return false;
  }

  key_decrypter = keyczar::Crypter::Read(
      *GetReader(algorithm, crypted_key_set, ""));
  verifier = keyczar::Signer::Read(
      *GetReader(signer_algorithm, crypted_key_set, ""));

  if (!key_decrypter || !verifier) {
    return false;
  }

  keyczar::SignedSessionDecrypter* crypter =
      SignedSessionDecrypter::NewSessionDecrypter(
          key_decrypter, verifier, session_material);

  if (!crypter) {
    return false;
  }

  crypter->set_encoding(Keyczar::NO_ENCODING);

  return crypter->SessionDecrypt(encrypted_data, &plaintext) &&
      plaintext == test_data_;
}

bool SignOperation::Generate(
    const std::string& algorithm, const DictionaryValue * generate_params,
    std::string * output) {
  keyczar::Keyczar* signer;
  std::string encoding, crypted_key_set, crypter_class;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set)) {
    return false;
  }
  signer = keyczar::Signer::Read(*GetReader(algorithm, crypted_key_set, ""));
  if (!signer) return false;
  if (encoding == "unencoded") {
    signer->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  if (!signer->Sign(test_data_, output)) return false;
  return true;
}

bool SignOperation::Test(
      const DictionaryValue * output_json, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params) {
  std::string output;
  if (!InputFromJson(output_json, &output)) return false;
  keyczar::Keyczar* verifier;
  std::string encoding, crypted_key_set, verifier_class, pub_key;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set) ||
      !test_params->GetString("class", &verifier_class) ||
      !test_params->GetString("pubKey", &pub_key)) {
    return false;
  }
  if (verifier_class == "signer") {
    verifier = keyczar::Signer::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else if (verifier_class == "verifier") {
    verifier = keyczar::Verifier::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else {
    return false;
  }
  if (!verifier) return false;
  if (encoding == "unencoded") {
    verifier->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  return verifier->Verify(test_data_, output);
}

bool AttachedSignOperation::Generate(
    const std::string& algorithm, const DictionaryValue * generate_params,
    std::string * output) {
  keyczar::Keyczar* signer;
  std::string encoding, crypted_key_set, crypter_class;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set)) {
    return false;
  }
  signer = keyczar::Signer::Read(*GetReader(algorithm, crypted_key_set, ""));
  if (!signer) return false;
  if (encoding == "unencoded") {
    signer->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  if (!signer->AttachedSign(test_data_, "", output)) return false;
  return true;
}

bool AttachedSignOperation::Test(
      const DictionaryValue * output_json, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params) {
  std::string output;
  if (!InputFromJson(output_json, &output)) return false;
  keyczar::Keyczar* verifier;
  std::string message, encoding, crypted_key_set, verifier_class, pub_key;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set) ||
      !test_params->GetString("class", &verifier_class) ||
      !test_params->GetString("pubKey", &pub_key)) {
    return false;
  }
  if (verifier_class == "signer") {
    verifier = keyczar::Signer::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else if (verifier_class == "verifier") {
    verifier = keyczar::Verifier::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else {
    return false;
  }
  if (!verifier) return false;
  if (encoding == "unencoded") {
    verifier->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }

  return verifier->AttachedVerify(output, "", &message) &&
      message == test_data_;
}

bool UnversionedSignOperation::Generate(
    const std::string& algorithm, const DictionaryValue * generate_params,
    std::string * output) {
  keyczar::Keyczar* signer;
  std::string encoding, crypted_key_set, crypter_class;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set)) {
    return false;
  }
  signer = keyczar::UnversionedSigner::Read(
      *GetReader(algorithm, crypted_key_set, ""));
  if (!signer) return false;
  if (encoding == "unencoded") {
    signer->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  if (!signer->Sign(test_data_, output)) return false;
  return true;
}

bool UnversionedSignOperation::Test(
      const DictionaryValue * output_json, const std::string& algorithm,
      const DictionaryValue * generate_params,
      const DictionaryValue * test_params) {
  std::string output;
  if (!InputFromJson(output_json, &output)) return false;
  keyczar::Keyczar* verifier;
  std::string encoding, crypted_key_set, verifier_class, pub_key;
  if (!generate_params->GetString("encoding", &encoding) ||
      !generate_params->GetString("cryptedKeySet", &crypted_key_set) ||
      !test_params->GetString("class", &verifier_class) ||
      !test_params->GetString("pubKey", &pub_key)) {
    return false;
  }
  if (verifier_class == "signer") {
    verifier = keyczar::UnversionedSigner::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else if (verifier_class == "verifier") {
    verifier = keyczar::UnversionedVerifier::Read(
        *GetReader(algorithm, crypted_key_set, pub_key));
  } else {
    return false;
  }
  if (!verifier) return false;
  if (encoding == "unencoded") {
    verifier->set_encoding(Keyczar::NO_ENCODING);
  } else if (encoding != "encoded") {
    return false;
  }
  return verifier->Verify(test_data_, output);
}

}  // namespace interop
}  // namespace keyczar
