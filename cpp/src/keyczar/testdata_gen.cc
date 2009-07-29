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

// Copied from src/keyczar/testdata_gen.cc
//
// Program used to generate src/keyczar/data/.
#include <string>

#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/string_util.h>
#include <keyczar/key_purpose.h>
#include <keyczar/key_status.h>
#include <keyczar/keyczar.h>
#include <keyczar/keyczar_tool.h>
#include <keyczar/keyset_encrypted_file_reader.h>

namespace {

static void WriteToFile(const std::string& data, const FilePath& dirname,
                        int version) {
  FilePath destination(dirname);
  const std::string basename = IntToString(version) + ".out";
  destination = destination.Append(basename);
  file_util::WriteFile(destination, data.data(), data.length());
}

}  // namespace

int main(int argc, char** argv) {
  // Destination directory
  const FilePath location(argv[1]);
  const std::string empty_path("");
  const std::string input = "This is some test data";
  const keyczar::keyczar_tool::KeyczarTool tool(
      keyczar::keyczar_tool::KeyczarTool::JSON_FILE);
  scoped_ptr<keyczar::KeyPurpose> encrypt_purpose(
      keyczar::KeyPurpose::Create("DECRYPT_AND_ENCRYPT"));
  scoped_ptr<keyczar::KeyPurpose> sign_purpose(
      keyczar::KeyPurpose::Create("SIGN_AND_VERIFY"));
  scoped_ptr<keyczar::KeyStatus> primary_status(
      keyczar::KeyStatus::Create("PRIMARY"));
  std::string encrypted, signature;

  {
    // AES
    const FilePath cur_location = location.Append("aes");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *encrypt_purpose, "Test", "");
    scoped_ptr<keyczar::Encrypter> encrypter;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0, empty_path);
      encrypter.reset(keyczar::Encrypter::Read(cur_location.value()));
      encrypter->Encrypt(input, &encrypted);
      WriteToFile(encrypted, cur_location, i);
    }
  }

  {
    // AES crypted
    const FilePath cur_location = location.Append("aes-crypted");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *encrypt_purpose, "Test", "");
    const FilePath aes_encrypter_path(location.Append("aes"));
     keyczar::KeysetEncryptedJSONFileReader encrypted_reader(
        cur_location, keyczar::Crypter::Read(aes_encrypter_path.value()));
    scoped_ptr<keyczar::Encrypter> encrypter;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0,
                     aes_encrypter_path.value());
      encrypter.reset(keyczar::Encrypter::Read(encrypted_reader));
      encrypter->Encrypt(input, &encrypted);
      WriteToFile(encrypted, cur_location, i);
    }
  }

  {
    // HMAC
    const FilePath cur_location = location.Append("hmac");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *sign_purpose, "Test", "");
    scoped_ptr<keyczar::Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0, empty_path);
      signer.reset(keyczar::Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }
  }

  {
    // DSA_PRIV
    const FilePath cur_location = location.Append("dsa");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *sign_purpose, "Test", "dsa");
    scoped_ptr<keyczar::Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0, empty_path);
      signer.reset(keyczar::Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }

    // DSA_PUB
    const FilePath destination = location.Append("dsa.public");
    file_util::CreateDirectory(destination);
    tool.CmdPubKey(cur_location.value(), destination.value(), empty_path);
  }

  {
    // ECDSA_PRIV
    const FilePath cur_location = location.Append("ecdsa");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *sign_purpose, "Test", "ecdsa");
    scoped_ptr<keyczar::Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0, empty_path);
      signer.reset(keyczar::Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }

    // ECDSA_PUB
    const FilePath destination = location.Append("ecdsa.public");
    file_util::CreateDirectory(destination);
    tool.CmdPubKey(cur_location.value(), destination.value(), empty_path);
  }

  {
    // RSA_PRIV SIGN
    const FilePath cur_location = location.Append("rsa-sign");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *sign_purpose, "Test", "rsa");
    scoped_ptr<keyczar::Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0, empty_path);
      signer.reset(keyczar::Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }

    // RSA_PUB VERIFY
    const FilePath destination = location.Append("rsa-sign.public");
    file_util::CreateDirectory(destination);
    tool.CmdPubKey(cur_location.value(), destination.value(), empty_path);
  }

  {
    // RSA_PRIV ENCRYPT
    const FilePath cur_location = location.Append("rsa");
    file_util::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), *encrypt_purpose, "Test", "rsa");
    scoped_ptr<keyczar::Encrypter> encrypter;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), *primary_status, 0, empty_path);
      encrypter.reset(keyczar::Encrypter::Read(cur_location.value()));
      encrypter->Encrypt(input, &encrypted);
      WriteToFile(encrypted, cur_location, i);
    }
  }

  return 0;
}
