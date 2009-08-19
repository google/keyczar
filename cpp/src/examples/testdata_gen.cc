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

// Program used to generate src/keyczar/data/.
#include <string>

#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/string_util.h>
#include <keyczar/key_purpose.h>
#include <keyczar/key_status.h>
#include <keyczar/keyczar.h>
#include <keyczar/keyczar_tool/keyczar_tool.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>

namespace {

static void WriteToFile(const std::string& data, const FilePath& dirname,
                        int version) {
  FilePath destination(dirname);
  const std::string basename = IntToString(version) + ".out";
  destination = destination.Append(basename);
  keyczar::base::WriteStringToFile(destination, data);
}

}  // namespace

namespace keyczar {
namespace gen {

void TestdataGen(const FilePath& location) {
  const std::string empty("");
  const std::string input = "This is some test data";
  const keyczar_tool::KeyczarTool tool(keyczar_tool::KeyczarTool::JSON_FILE);
  const KeyPurpose::Type encrypt_purpose = KeyPurpose::DECRYPT_AND_ENCRYPT;
  const KeyPurpose::Type sign_purpose = KeyPurpose::SIGN_AND_VERIFY;
  const KeyStatus::Type primary_status = KeyStatus::PRIMARY;
  std::string encrypted, signature;

  {
    // AES
    const FilePath cur_location = location.Append("aes");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), encrypt_purpose, "Test",
                   keyczar_tool::KeyczarTool::SYMMETRIC);
    scoped_ptr<Encrypter> encrypter;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::NONE, empty);
      encrypter.reset(Encrypter::Read(cur_location.value()));
      encrypter->Encrypt(input, &encrypted);
      WriteToFile(encrypted, cur_location, i);
    }
  }

  {
    // AES crypted
    const FilePath cur_location = location.Append("aes-crypted");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), encrypt_purpose, "Test",
                   keyczar_tool::KeyczarTool::SYMMETRIC);
    const FilePath aes_encrypter_path(location.Append("aes"));
    rw::KeysetEncryptedJSONFileReader encrypted_reader(
        cur_location, Crypter::Read(aes_encrypter_path.value()));
    scoped_ptr<Encrypter> encrypter;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::CRYPTER,
                     aes_encrypter_path.value());
      encrypter.reset(Encrypter::Read(encrypted_reader));
      encrypter->Encrypt(input, &encrypted);
      WriteToFile(encrypted, cur_location, i);
    }
  }

  {
    // HMAC
    const FilePath cur_location = location.Append("hmac");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), sign_purpose, "Test",
                   keyczar_tool::KeyczarTool::SYMMETRIC);
    scoped_ptr<Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::NONE, empty);
      signer.reset(Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }
  }

  {
    // DSA_PRIV
    const FilePath cur_location = location.Append("dsa");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), sign_purpose, "Test",
                   keyczar_tool::KeyczarTool::DSA);
    scoped_ptr<Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::NONE, empty);
      signer.reset(Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }

    // DSA_PUB
    const FilePath destination = location.Append("dsa.public");
    base::CreateDirectory(destination);
    tool.CmdPubKey(cur_location.value(), destination.value(),
                   keyczar_tool::KeyczarTool::NONE, empty);
  }

  {
    // ECDSA_PRIV
    const FilePath cur_location = location.Append("ecdsa");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), sign_purpose, "Test",
                   keyczar_tool::KeyczarTool::ECDSA);
    scoped_ptr<Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::NONE, empty);
      signer.reset(Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }

    // ECDSA_PUB
    const FilePath destination = location.Append("ecdsa.public");
    base::CreateDirectory(destination);
    tool.CmdPubKey(cur_location.value(), destination.value(),
                   keyczar_tool::KeyczarTool::NONE, empty);
  }

  {
    // RSA_PRIV SIGN
    const FilePath cur_location = location.Append("rsa-sign");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), sign_purpose, "Test",
                   keyczar_tool::KeyczarTool::RSA);
    scoped_ptr<Signer> signer;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::NONE, empty);
      signer.reset(Signer::Read(cur_location.value()));
      signer->Sign(input, &signature);
      WriteToFile(signature, cur_location, i);
    }

    // RSA_PUB VERIFY
    const FilePath destination = location.Append("rsa-sign.public");
    base::CreateDirectory(destination);
    tool.CmdPubKey(cur_location.value(), destination.value(),
                   keyczar_tool::KeyczarTool::NONE, empty);
  }

  {
    // RSA_PRIV ENCRYPT
    const FilePath cur_location = location.Append("rsa");
    base::CreateDirectory(cur_location);
    tool.CmdCreate(cur_location.value(), encrypt_purpose, "Test",
                   keyczar_tool::KeyczarTool::RSA);
    scoped_ptr<Encrypter> encrypter;
    for (int i = 1; i < 3; ++i) {
      tool.CmdAddKey(cur_location.value(), primary_status, 0,
                     keyczar_tool::KeyczarTool::NONE, empty);
      encrypter.reset(Encrypter::Read(cur_location.value()));
      encrypter->Encrypt(input, &encrypted);
      WriteToFile(encrypted, cur_location, i);
    }
  }
}

}  // namespace keyczar
}  // namespace gen

int main(int argc, char** argv) {
  if (argc != 2)
    return 1;

  // Destination directory
  const FilePath location(argv[1]);
  keyczar::gen::TestdataGen(location);
  return 0;
}

