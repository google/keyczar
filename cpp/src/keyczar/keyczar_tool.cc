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
#include "keyczar/keyczar_tool.h"

#include <stdio.h>

#include "base/logging.h"
#include "base/string_util.h"
#include "base/sys_string_conversions.h"
#include "base/values.h"

#include "keyczar/key_type.h"
#include "keyczar/keyczar.h"
#include "keyczar/keyset.h"
#include "keyczar/keyset_encrypted_file_reader.h"
#include "keyczar/keyset_encrypted_file_writer.h"

namespace {

static const char kUsageMessage[] =
    "Usage: keyczart command flags\n"
    "Commands: create addkey pubkey promote demote revoke\n"
    "Flags: location name size status purpose destination version asymmetric\n"
    "       crypter\n\n"
    "Command Usage:\n"
    "create --location=/path/to/keys --purpose=(crypt|sign) --name=\"A name\""
    " --asymmetric=(dsa|rsa)\n"
    "   Creates a new, empty key set in the given location. This key set must\n"
    "   have a purpose of either \"crypt\" or \"sign\" and may optionally be\n"
    "   given a name. The optional asymmetric flag will generate a public \n"
    "   key set of the given algorithm. The \"dsa\" asymmetric value is valid\n"
    "   only for sets with \"sign\" purpose. with the given purpose.\n\n"
    "addkey --location=/path/to/keys --status=(active|primary) --size=size "
    "--crypter=crypterLocation\n"
    "   Adds a new key to an existing key set. Optionally specify a purpose,\n"
    "   which is active by default. Optionally specify a key size in bits.\n"
    "   Also optionally specify the location of a set of crypting keys, which\n"
    "   will be used to encrypt this key set.\n\n"
    "pubkey --location=/path/to/keys --destination=/destination"
    " --crypter=crypterLocation\n"
    "   Extracts public keys from a given key set and writes them to the\n"
    "   destination. The \"pubkey\" command Only works for key sets that were\n"
    "   created with the \"--asymmetric\" flag.\n\n"
    "promote --location=/path/to/keys --version=versionNumber\n"
    "   Promotes the status of the given key version in the given location.\n"
    "   Active keys are promoted to primary (which demotes any existing\n"
    "   primary key to active). Keys scheduled for revocation are promoted to\n"
    "   be active.\n\n"
    "demote --location=/path/to/keys --version=versionNumber\n"
    "   Demotes the status of the given key version in the given location.\n"
    "   Primary keys are demoted to active. Active keys are scheduled for\n"
    "   revocation.\n\n"
    "revoke --location=/path/to/keys --version=versionNumber\n"
    "   Revokes the key of the given version number. This key must have been\n"
    "   scheduled for revocation by the promote command. WARNING: The key\n"
    "   will be destroyed.\n\n";

static void PrintUsage() {
  printf("%s", kUsageMessage);
}

static void MissingArgument(const std::wstring& argument) {
  LOG(ERROR) << "Missing argument '" << argument << "'.";
}

static bool GetSwitchValue(const CommandLine& command_line,
                           const std::wstring& switch_string,
                           std::string* value, bool optionnal) {
  if (value == NULL)
    return false;

  if (!command_line.HasSwitch(switch_string)) {
    if (!optionnal)
      MissingArgument(switch_string);
    return false;
  }

  value->assign(base::SysWideToUTF8(
                    command_line.GetSwitchValue(switch_string)));
  return true;
}

}  // namespace

namespace keyczar {

namespace keyczar_tool {

bool KeyczarTool::Init(int argc, char** argv) {
  // Initializes command line singleton
  CommandLine::Init(argc, argv);
  command_line_ = const_cast<CommandLine*>(CommandLine::ForCurrentProcess());
  if (command_line_ == NULL)
    return false;
  return true;
}

bool KeyczarTool::ProcessCommandLine() {
  if (command_line_->HasSwitch(L"help")) {
    PrintUsage();
    return true;
  }

  std::vector<std::wstring> loose_values = command_line_->GetLooseValues();
  if (loose_values.empty()) {
    LOG(ERROR) << "A command must be provided.";
    return false;
  }
  if (loose_values.size() > 1) {
    LOG(ERROR) << "A single command must be provided.";
    return false;
  }

  // A location is expected in every case.
  std::string location;
  if (!GetSwitchValue(*command_line_, L"location", &location, false))
    return false;

  // Command create
  if (loose_values[0] == L"create") {
    // purpose
    std::string purpose_string;
    if (!GetSwitchValue(*command_line_, L"purpose", &purpose_string, false))
      return false;
    scoped_ptr<KeyPurpose> purpose;
    if (purpose_string == "sign") {
      purpose.reset(KeyPurpose::Create("SIGN_AND_VERIFY"));
    } else {
      if (purpose_string == "crypt") {
        purpose.reset(KeyPurpose::Create("DECRYPT_AND_ENCRYPT"));
      } else {
        LOG(ERROR) << "Invalid purpose '" << purpose_string << "'.";
        return false;
      }
    }

    // name
    std::string name_string("Test");
    GetSwitchValue(*command_line_, L"name", &name_string, true);

    // asymmetric
    std::string asymmetric_string;
    GetSwitchValue(*command_line_, L"asymmetric", &asymmetric_string, true);

    return CmdCreate(location, *purpose, name_string, asymmetric_string);
  }

  // Command addkey
  if (loose_values[0] == L"addkey") {
    // status
    std::string status_string("ACTIVE");
    GetSwitchValue(*command_line_, L"status", &status_string, true);
    scoped_ptr<KeyStatus> status(KeyStatus::Create(
                                     StringToUpperASCII(status_string)));
    if (status.get() == NULL) {
      LOG(ERROR) << "Invalid status '" << status_string << "'.";
      return false;
    }

    // size
    std::string size_string;
    GetSwitchValue(*command_line_, L"size", &size_string, true);
    int size = 0;
    if (!size_string.empty() && !StringToInt(size_string, &size)) {
      LOG(ERROR) << "Invalid size '" << size_string << "'.";
      return false;
    }

    // crypter
    std::string crypter;
    GetSwitchValue(*command_line_, L"crypter", &crypter, true);

    return CmdAddKey(location, *status, size, crypter);
  }

  // Command pubkey
  if (loose_values[0] == L"pubkey") {
    // destination
    std::string destination;
    if (!GetSwitchValue(*command_line_, L"destination", &destination, false))
      return false;

    // crypter
    std::string crypter;
    GetSwitchValue(*command_line_, L"crypter", &crypter, true);

    return CmdPubKey(location, destination, crypter);
  }

  // A version number is expected by all the remaining commands.
  std::string version_string;
  if (!GetSwitchValue(*command_line_, L"version", &version_string, false))
    return false;
  int version = 0;
  if (!StringToInt(version_string, &version)) {
    LOG(ERROR) << "Invalid version '" << version_string << "'.";
    return false;
  }

  // Command promote
  if (loose_values[0] == L"promote")
    return CmdPromote(location, version);
  // Command demote
  if (loose_values[0] == L"demote")
    return CmdDemote(location, version);
  // Command revoke
  if (loose_values[0] == L"revoke")
    return CmdRevoke(location, version);

  LOG(ERROR) << "Unknown command '" << loose_values[0] << "'.";
  PrintUsage();
  return false;
}

bool KeyczarTool::CmdCreate(const std::string& location,
                            const KeyPurpose& key_purpose,
                            const std::string& name,
                            const std::string& asymmetric) const {
  KeysetFileReader reader(location);
  scoped_ptr<Value> metadata_value(reader.ReadMetadata());
  if (metadata_value.get() != NULL) {
    LOG(ERROR) << "Metadata already exists, cannot overwrite.";
    return false;
  }
  metadata_value.reset();

  Keyset keyset;
  KeysetFileWriter writer(location);
  keyset.AddObserver(&writer);

  scoped_ptr<KeyType> key_type;
  if (key_purpose.type() == KeyPurpose::SIGN_AND_VERIFY) {
    if (asymmetric.empty()) {
      key_type.reset(KeyType::Create("HMAC_SHA1"));
    } else {
      if (asymmetric == "rsa") {
        key_type.reset(KeyType::Create("RSA_PRIV"));
      } else {
        if (asymmetric == "dsa") {
          key_type.reset(KeyType::Create("DSA_PRIV"));
        } else {
          LOG(ERROR) << "Invalid asymmetric argument '" << asymmetric << "'.";
          return false;
        }
      }
    }
  } else {
    if (key_purpose.type() == KeyPurpose::DECRYPT_AND_ENCRYPT) {
      if (asymmetric.empty()) {
        key_type.reset(KeyType::Create("AES"));
      } else {
        if (asymmetric == "rsa") {
          key_type.reset(KeyType::Create("RSA_PRIV"));
        } else {
          LOG(ERROR) << "Invalid asymmetric argument '" << asymmetric << "'.";
          return false;
        }
      }
    } else {
      std::string purpose_string;
      key_purpose.GetName(&purpose_string);
      LOG(ERROR) << "Invalid key purpose '" << purpose_string << "'.";
      return false;
    }
  }

  KeysetMetadata* metadata = NULL;
  metadata = new KeysetMetadata(name, key_type.release(),
                                new KeyPurpose(key_purpose.type()),
                                false, 1);
  if (metadata == NULL)
    return false;

  keyset.set_metadata(metadata);
  return true;
}

bool KeyczarTool::CmdAddKey(const std::string& location,
                            const KeyStatus& key_status,
                            int size,
                            const std::string& crypter_location) const {
  scoped_ptr<KeysetFileReader> reader(GetFileReader(location,
                                                    crypter_location));
  if (reader.get() == NULL)
    return false;

  scoped_ptr<Keyset> keyset(Keyset::Read(*reader, true));
  if (keyset.get() == NULL)
    return false;

  scoped_ptr<KeysetFileWriter> writer(GetFileWriter(location,
                                                    crypter_location));
  if (writer.get() == NULL)
    return false;

  keyset->AddObserver(writer.get());

  if (size == 0) {
    if (keyset->GenerateDefaultKeySize(key_status.type()) == 0)
      return false;
  }  else {
    if (keyset->GenerateKey(key_status.type(), size) == 0)
      return false;
  }

  if (!crypter_location.empty())
    keyset->set_encrypted(true);
  return true;
}

bool KeyczarTool::CmdPubKey(const std::string& location,
                            const std::string& destination,
                            const std::string& crypter_location) const {
  scoped_ptr<KeysetFileReader> reader(GetFileReader(location,
                                                    crypter_location));
  if (reader.get() == NULL)
    return false;

  scoped_ptr<Keyset> keyset(Keyset::Read(*reader, true));
  if (keyset.get() == NULL)
    return false;

  KeysetFileWriter writer(destination);
  return keyset->PublicKeyExport(writer);
}

bool KeyczarTool::CmdPromote(const std::string& location, int version) const {
  KeysetFileReader reader(location);

  scoped_ptr<Keyset> keyset(Keyset::ReadMetadataOnly(reader));
  if (keyset.get() == NULL)
    return false;

  KeysetFileWriter writer(location);
  keyset->AddObserver(&writer);

  return keyset->PromoteKey(version);
}

bool KeyczarTool::CmdDemote(const std::string& location, int version) const {
  KeysetFileReader reader(location);

  scoped_ptr<Keyset> keyset(Keyset::ReadMetadataOnly(reader));
  if (keyset.get() == NULL)
    return false;

  KeysetFileWriter writer(location);
  keyset->AddObserver(&writer);

  return keyset->DemoteKey(version);
}

bool KeyczarTool::CmdRevoke(const std::string& location, int version) const {
  KeysetFileReader reader(location);

  scoped_ptr<Keyset> keyset(Keyset::ReadMetadataOnly(reader));
  if (keyset.get() == NULL)
    return false;

  KeysetFileWriter writer(location);
  keyset->AddObserver(&writer);

  // TODO(seb): currently the key version is not erased from disk.
  return keyset->RevokeKey(version);
}

KeysetFileReader* KeyczarTool::GetFileReader(
    const std::string& location, const std::string& crypter_location) const {
  scoped_ptr<KeysetFileReader> reader;
  scoped_ptr<Crypter> crypter;

  if (crypter_location.empty()) {
    reader.reset(new KeysetFileReader(location));
  } else {
    crypter.reset(Crypter::Read(crypter_location));
    if (crypter.get() == NULL)
      return NULL;
    reader.reset(new KeysetEncryptedFileReader(location, crypter.release()));
  }
  return reader.release();
}

KeysetFileWriter* KeyczarTool::GetFileWriter(
    const std::string& location, const std::string& crypter_location) const {
  scoped_ptr<KeysetFileWriter> writer;
  scoped_ptr<Encrypter> encrypter;

  if (crypter_location.empty()) {
    writer.reset(new KeysetFileWriter(location));
  } else {
    encrypter.reset(Encrypter::Read(crypter_location));
    if (encrypter.get() == NULL)
      return false;

    writer.reset(new KeysetEncryptedFileWriter(location, encrypter.release()));
  }
  return writer.release();
}

}  // namespace keyczar_tool

}  // namespace keyczar
