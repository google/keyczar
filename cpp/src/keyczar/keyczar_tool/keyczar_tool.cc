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
#include <keyczar/keyczar_tool/keyczar_tool.h>

#include <stdio.h>

#include <keyczar/base/logging.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/base/string_util.h>
#include <keyczar/base/values.h>
#include <keyczar/key_type.h>
#include <keyczar/keyczar.h>
#include <keyczar/keyset.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_writer.h>

namespace {

static const char kUsageMessage[] =
    "Usage: keyczart command flags\n"
    "Commands: create addkey importkey pubkey promote demote revoke\n"
    "Flags: location name size status purpose destination version asymmetric\n"
    "       crypter key passphrase pass form\n\n"
    "Command usage:\n\n"
    "create --location=/path/to/keys --purpose=(crypt|sign) --name=\"A name\""
    " \\\n"
    "       --asymmetric=(dsa|rsa|ecdsa)\n"
    "   Creates a new, empty key set in the given location. This key set must\n"
    "   have a purpose of either \"crypt\" or \"sign\" and may optionally be\n"
    "   given a name. The optional asymmetric flag will generate a public \n"
    "   key set of the given algorithm. The \"dsa\" and \"ecdsa\" asymmetric\n"
    "   values are valid only for sets with \"sign\" purpose.\n\n"
    "addkey --location=/path/to/keys --status=(active|primary) --size=size \\\n"
    "       --crypter=crypterLocation --pass=\"password\"\n"
    "   Adds a new key to an existing key set. Optionally specify a purpose,\n"
    "   which is \"active\" by default. Optionally specify a key size in\n"
    "   bits. Also optionally specify the location of a set of crypting keys,\n"
    "   which will be used to encrypt this key set. Alternatively for the \n"
    "   same purpose a password may be required. If option pass is provided \n"
    "   without value then a password will be prompted interactively. It is\n"
    "   currently easier to use the same password for every keys in the same\n"
    "   key set otherwise it will be necessary to provide its own code to \n"
    "   read this key set.\n\n"
    "importkey --location=/path/to/keys --status=(active|primary) \\\n"
    "          --key=keyFileLocation --passphrase=\"passphrase\" \\\n"
    "          --crypter=crypterLocation --pass=\"password\"\n"
    "   Imports a private key (RSA, DSA or ECDSA) to an existing key set.\n"
    "   keyFileLocation is the key file to import it must have a PEM or PKCS8\n"
    "   representation. Optionally provide its passphrase. If a mandatory\n"
    "   passphrase is not specified as argument it will be prompted\n"
    "   interactively from the shell when this command is executed.\n"
    "   Optionally specify a purpose, which is \"active\" by default. Also\n"
    "   optionally the location of a set of crypting keys, which will be\n"
    "   used to encrypt this key set or optionally use a password (read\n"
    "   complete description in command addkey).\n\n"
    "exportkey --location=/path/to/keys --dest=destinationFile \\\n"
    "          --passphrase=\"passphrase\" --crypter=crypterLocation \\\n"
    "          --pass=\"password\"\n"
    "   Exports current primary private key to destinationFile using PKCS8\n"
    "   format. A crypterLocation or a password can be required to decrypt\n"
    "   the loaded key set. A passphrase is used to encrypt the exported key.\n"
    "   If not provided it will be prompted at execution.\n\n"
    "pubkey --location=/path/to/keys --destination=/path/to/destination \\\n"
    "       --crypter=crypterLocation --pass=\"password\"\n"
    "   Extracts public keys from a given key set and writes them to the\n"
    "   destination. The \"pubkey\" command only works for key sets that were\n"
    "   created with the \"--asymmetric\" flag. Also optionally specify the \n"
    "   location of a set of crypting keys, which will be used to encrypt \n"
    "   this key set or optionally use a password.\n\n"
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

static void MissingArgument(const std::string& argument) {
  LOG(ERROR) << "Missing argument '" << argument << "'.";
}

static bool GetSwitchValue(const keyczar::base::CommandLine& cmdl,
                           const std::string& switch_string,
                           std::string* value,
                           bool optionnal) {
  if (value == NULL)
    return false;

  if (!cmdl.HasSwitch(switch_string)) {
    if (!optionnal)
      MissingArgument(switch_string);
    return false;
  }

  value->assign(cmdl.GetSwitchValue(switch_string));
  return true;
}

}  // namespace

namespace keyczar {
namespace keyczar_tool {

static KeyczarTool::Cipher GetCipher(const std::string& cipher) {
  if (cipher == "rsa")
    return KeyczarTool::RSA;
  if (cipher == "dsa")
    return KeyczarTool::DSA;
  if (cipher == "ecdsa")
    return KeyczarTool::ECDSA;
  return KeyczarTool::SYMMETRIC;
}

// static
bool KeyczarTool::ProcessCommandLine(LocationType location_type, int argc,
                                     char** argv) {
  KeyczarTool kt(location_type);
  base::CommandLine cl(argc, argv);
  return kt.DoProcessCommandLine(cl);
}

bool KeyczarTool::CmdCreate(const std::string& location,
                            KeyPurpose::Type key_purpose,
                            const std::string& name,
                            Cipher cipher) const {
  scoped_ptr<rw::KeysetReader> reader(GetReader(location, NONE, ""));
  if (reader.get() == NULL)
    return false;

  scoped_ptr<Value> metadata_value(reader->ReadMetadata());
  if (metadata_value.get() != NULL) {
    LOG(ERROR) << "Metadata already exists, cannot overwrite.";
    return false;
  }
  metadata_value.reset();

  Keyset keyset;

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(location, NONE, ""));
  if (writer.get() == NULL)
    return false;

  keyset.AddObserver(writer.get());

  KeyType::Type key_type;
  if (key_purpose == KeyPurpose::SIGN_AND_VERIFY) {
    switch (cipher) {
      case SYMMETRIC:
#ifdef COMPAT_KEYCZAR_06B
        key_type = KeyType::HMAC_SHA1;
#else
        key_type = KeyType::HMAC;
#endif
        break;
      case RSA:
        key_type = KeyType::RSA_PRIV;
        break;
      case DSA:
        key_type = KeyType::DSA_PRIV;
        break;
      case ECDSA:
        key_type = KeyType::ECDSA_PRIV;
        break;
      default:
        LOG(ERROR) << "Unknown signature cipher.";
        return false;
    }
  } else {
    if (key_purpose != KeyPurpose::DECRYPT_AND_ENCRYPT) {
      LOG(ERROR) << "Invalid key purpose '"
                 << KeyPurpose::GetNameFromType(key_purpose) << "'.";
      return false;
    }

    switch (cipher) {
      case SYMMETRIC:
        key_type = KeyType::AES;
        break;
      case RSA:
        key_type = KeyType::RSA_PRIV;
        break;
      default:
        LOG(ERROR) << "Unknown encryption cipher.";
        return false;
    }
  }

  KeysetMetadata* metadata = NULL;
  metadata = new KeysetMetadata(name, key_type, key_purpose, false, 1);
  if (metadata == NULL)
    return false;

  keyset.set_metadata(metadata);
  return true;
}

int KeyczarTool::CmdAddKey(const std::string& location,
                           KeyStatus::Type key_status,
                           int size,
                           KeyEncryption key_enc_type,
                           const std::string& key_enc_value) const {
  scoped_ptr<rw::KeysetReader> reader(GetReader(location, key_enc_type,
                                                key_enc_value));
  if (reader.get() == NULL)
    return 0;

  // FIXME: awfull
  if (key_enc_type == PBE && key_enc_value.empty())
    LOG(INFO) << "For each key of this key set enter its password";

  scoped_ptr<Keyset> keyset(Keyset::Read(*reader, true));
  if (keyset.get() == NULL)
    return 0;

  CHECK(keyset->metadata());
  if (!keyset->metadata()->Empty()) {
    bool is_encrypted = keyset->metadata()->encrypted();
    if ((key_enc_type != NONE && !is_encrypted) ||
        (key_enc_type == NONE && is_encrypted)) {
      LOG(ERROR) << "Cannot add key: uncompatible 'encrypted' "
                 << "key set field value.";
      return 0;
    }
  }

  // FIXME: awfull
  if (key_enc_type == PBE && key_enc_value.empty())
    LOG(INFO) << "Adding new key...";

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(location, key_enc_type,
                                                key_enc_value));
  if (writer.get() == NULL)
    return 0;

  keyset->AddObserver(writer.get());

  if (key_enc_type != NONE)
    keyset->set_encrypted(true);

  if (size == 0)
    return keyset->GenerateDefaultKeySize(key_status);
  return keyset->GenerateKey(key_status, size);
}

int KeyczarTool::CmdImportKey(const std::string& location,
                              KeyStatus::Type key_status,
                              const std::string& filename,
                              const std::string* passphrase,
                              KeyEncryption key_enc_type,
                              const std::string& key_enc_value,
                              bool public_key) const {
  if (public_key) {
    NOTIMPLEMENTED();
    return 0;
  }

  scoped_ptr<rw::KeysetReader> reader(GetReader(location, key_enc_type,
                                                key_enc_value));
  if (reader.get() == NULL)
    return 0;

  // FIXME: awfull
  if (key_enc_type == PBE && key_enc_value.empty())
    LOG(INFO) << "For each key of this key set enter its password";

  scoped_ptr<Keyset> keyset(Keyset::Read(*reader, true));
  if (keyset.get() == NULL)
    return 0;

  CHECK(keyset->metadata());
  if (!keyset->metadata()->Empty()) {
    bool is_encrypted = keyset->metadata()->encrypted();
    if ((key_enc_type != NONE && !is_encrypted) ||
        (key_enc_type == NONE && is_encrypted)) {
      LOG(ERROR) << "Cannot add key: uncompatible 'encrypted' "
                 << "key set field value.";
      return 0;
    }
  }

  // FIXME: awfull
  if (key_enc_type == PBE && key_enc_value.empty())
    LOG(INFO) << "Importing key...";

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(location, key_enc_type,
                                                key_enc_value));
  if (writer.get() == NULL)
    return 0;

  keyset->AddObserver(writer.get());

  if (key_enc_type != NONE)
    keyset->set_encrypted(true);

  return keyset->ImportPrivateKey(key_status, filename, passphrase);
}

bool KeyczarTool::CmdExportKey(const std::string& location,
                               const std::string& filename,
                               const std::string* passphrase,
                               KeyEncryption key_enc_type,
                               const std::string& key_enc_value,
                               bool public_key) const {
  if (public_key) {
    NOTIMPLEMENTED();
    return false;
  }

  scoped_ptr<rw::KeysetReader> reader(GetReader(location, key_enc_type,
                                                key_enc_value));
  if (reader.get() == NULL)
    return false;

  // FIXME: awfull
  if (key_enc_type == PBE && key_enc_value.empty())
    LOG(INFO) << "For each key of this key set enter its password";

  scoped_ptr<Keyset> keyset(Keyset::Read(*reader, true));
  if (keyset.get() == NULL) {
    LOG(INFO) << "Export failed:  No keyset found";
    return false;
  }

  bool result = keyset->ExportPrivateKey(filename, passphrase);
}

bool KeyczarTool::CmdPubKey(const std::string& location,
                            const std::string& destination,
                            KeyEncryption key_enc_type,
                            const std::string& key_enc_value) const {
  scoped_ptr<rw::KeysetReader> reader(GetReader(location, key_enc_type,
                                                key_enc_value));
  if (reader.get() == NULL)
    return false;

  // FIXME: awfull
  if (key_enc_type == PBE && key_enc_value.empty())
    LOG(INFO) << "For each key of this key set enter its password";

  scoped_ptr<Keyset> keyset(Keyset::Read(*reader, true));
  if (keyset.get() == NULL)
    return false;

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(destination, NONE, ""));
  if (writer.get() == NULL)
    return false;

  return keyset->PublicKeyExport(*writer);
}

bool KeyczarTool::CmdPromote(const std::string& location, int version) const {
  scoped_ptr<rw::KeysetReader> reader(GetReader(location, NONE, ""));
  if (reader.get() == NULL)
    return false;

  scoped_ptr<Keyset> keyset(Keyset::ReadMetadataOnly(*reader));
  if (keyset.get() == NULL)
    return false;

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(location, NONE, ""));
  if (writer.get() == NULL)
    return false;

  keyset->AddObserver(writer.get());

  return keyset->PromoteKey(version);
}

bool KeyczarTool::CmdDemote(const std::string& location, int version) const {
  scoped_ptr<rw::KeysetReader> reader(GetReader(location, NONE, ""));
  if (reader.get() == NULL)
    return false;

  scoped_ptr<Keyset> keyset(Keyset::ReadMetadataOnly(*reader));
  if (keyset.get() == NULL)
    return false;

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(location, NONE, ""));
  if (writer.get() == NULL)
    return false;

  keyset->AddObserver(writer.get());

  return keyset->DemoteKey(version);
}

bool KeyczarTool::CmdRevoke(const std::string& location, int version) const {
  scoped_ptr<rw::KeysetReader> reader(GetReader(location, NONE, ""));
  if (reader.get() == NULL)
    return false;

  scoped_ptr<Keyset> keyset(Keyset::ReadMetadataOnly(*reader));
  if (keyset.get() == NULL)
    return false;

  scoped_ptr<rw::KeysetWriter> writer(GetWriter(location, NONE, ""));
  if (writer.get() == NULL)
    return false;

  keyset->AddObserver(writer.get());

  // TODO(seb): currently the key version is not erased from disk.
  return keyset->RevokeKey(version);
}

void KeyczarTool::set_location_type(LocationType location_type) {
  location_type_ = location_type;
}

bool KeyczarTool::DoProcessCommandLine(const base::CommandLine& cmdl) {
  if (cmdl.HasSwitch("help")) {
    PrintUsage();
    return true;
  }

  std::vector<std::string> loose_values = cmdl.GetLooseValues();
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
  if (!GetSwitchValue(cmdl, "location", &location, false))
    return false;

  // A new output format can always be provided and its default representation
  // format is JSON.
  std::string location_type_string("json");
  GetSwitchValue(cmdl, "form", &location_type_string, true);
  if (location_type_string == "json" && location_type_ != JSON_FILE)
    set_location_type(JSON_FILE);

  // Command create
  if (loose_values[0] == "create") {
    // purpose
    std::string purpose_string;
    if (!GetSwitchValue(cmdl, "purpose", &purpose_string, false))
      return false;
    KeyPurpose::Type purpose;
    if (purpose_string == "sign") {
      purpose = KeyPurpose::SIGN_AND_VERIFY;
    } else {
      if (purpose_string == "crypt") {
        purpose = KeyPurpose::DECRYPT_AND_ENCRYPT;
      } else {
        LOG(ERROR) << "Invalid purpose '" << purpose_string << "'.";
        return false;
      }
    }

    // name
    std::string name_string("Test");
    GetSwitchValue(cmdl, "name", &name_string, true);

    // asymmetric
    std::string asymmetric_string;
    if (GetSwitchValue(cmdl, "asymmetric", &asymmetric_string, true)
        && asymmetric_string.empty()) {
      LOG(INFO) << "Asymmetric key type must be one of rsa, dsa or ecsda";
      return false;
    }

    const Cipher cipher = GetCipher(asymmetric_string);
    return CmdCreate(location, purpose, name_string, cipher);
  }

  // Command addkey
  if (loose_values[0] == "addkey") {
    // status
    std::string status_string("ACTIVE");
    GetSwitchValue(cmdl, "status", &status_string, true);
    KeyStatus::Type status = KeyStatus::GetTypeFromName(
        StringToUpperASCII(status_string));
    if (status == KeyStatus::UNDEF) {
      LOG(ERROR) << "Invalid status '" << status_string << "'.";
      return false;
    }

    // size
    std::string size_string;
    GetSwitchValue(cmdl, "size", &size_string, true);

    char* enptr = NULL;
    int size = strto32(size_string.c_str(), &enptr, 10);

    // Key encryption
    KeyEncryption key_enc_type = NONE;
    base::ScopedSafeString key_enc_value(new std::string());

    // crypter
    if (GetSwitchValue(cmdl, "crypter", key_enc_value.get(), true))
      key_enc_type = CRYPTER;

    // pbe password
    if (GetSwitchValue(cmdl, "pass", key_enc_value.get(), true)) {
      if (key_enc_type != NONE) {
        LOG(ERROR) << "Cannot specify both a crypter and a PBE password.";
        return false;
      }
      key_enc_type = PBE;
    }

    return CmdAddKey(location, status, size, key_enc_type, *key_enc_value);
  }

  // Command importkey
  if (loose_values[0] == "importkey") {
    // status
    std::string status_string("ACTIVE");
    GetSwitchValue(cmdl, "status", &status_string, true);
    KeyStatus::Type status = KeyStatus::GetTypeFromName(
        StringToUpperASCII(status_string));
    if (status == KeyStatus::UNDEF) {
      LOG(ERROR) << "Invalid status '" << status_string << "'.";
      return false;
    }

    // filename
    std::string key_filename;
    if (!GetSwitchValue(cmdl, "key", &key_filename, false))
      return false;

    // passphrase
    base::ScopedSafeString passphrase(new std::string());
    if (!GetSwitchValue(cmdl, "passphrase", passphrase.get(), true))
      passphrase.reset(NULL);

    // Key encryption
    KeyEncryption key_enc_type = NONE;
    base::ScopedSafeString key_enc_value(new std::string());

    // crypter
    if (GetSwitchValue(cmdl, "crypter", key_enc_value.get(), true))
      key_enc_type = CRYPTER;

    // pbe password
    if (GetSwitchValue(cmdl, "pass", key_enc_value.get(), true)) {
      if (key_enc_type != NONE) {
        LOG(ERROR) << "Cannot specify both a crypter and a PBE password.";
        return false;
      }
      key_enc_type = PBE;
    }

    return CmdImportKey(location, status, key_filename, passphrase.get(),
                        key_enc_type, *key_enc_value, false);
  }

  // Command exportkey
  if (loose_values[0] == "exportkey") {
    // filename
    std::string dst_filename;
    if (!GetSwitchValue(cmdl, "dest", &dst_filename, false))
      return false;

    // passphrase
    base::ScopedSafeString passphrase(new std::string());
    if (!GetSwitchValue(cmdl, "passphrase", passphrase.get(), true))
      passphrase.reset(NULL);

    // Key encryption
    KeyEncryption key_enc_type = NONE;
    base::ScopedSafeString key_enc_value(new std::string());

    // crypter
    if (GetSwitchValue(cmdl, "crypter", key_enc_value.get(), true))
      key_enc_type = CRYPTER;

    // pbe password
    if (GetSwitchValue(cmdl, "pass", key_enc_value.get(), true)) {
      if (key_enc_type != NONE) {
        LOG(ERROR) << "Cannot specify both a crypter and a PBE password.";
        return false;
      }
      key_enc_type = PBE;
    }

    return CmdExportKey(location, dst_filename, passphrase.get(),
                        key_enc_type, *key_enc_value, false);
  }

  // Command pubkey
  if (loose_values[0] == "pubkey") {
    // destination
    std::string destination;
    if (!GetSwitchValue(cmdl, "destination", &destination, false))
      return false;

    // Key encryption
    KeyEncryption key_enc_type = NONE;
    base::ScopedSafeString key_enc_value(new std::string());

    // crypter
    if (GetSwitchValue(cmdl, "crypter", key_enc_value.get(), true))
      key_enc_type = CRYPTER;

    // pbe password
    if (GetSwitchValue(cmdl, "pass", key_enc_value.get(), true)) {
      if (key_enc_type != NONE) {
        LOG(ERROR) << "Cannot specify both a crypter and a PBE password.";
        return false;
      }
      key_enc_type = PBE;
    }

    return CmdPubKey(location, destination, key_enc_type, *key_enc_value);
  }

  // A version number is expected by all the remaining commands.
  std::string version_string;
  if (!GetSwitchValue(cmdl, "version", &version_string, false))
    return false;

  char* enptr = NULL;
  int version = strto32(version_string.c_str(), &enptr, 10);

  // Command promote
  if (loose_values[0] == "promote")
    return CmdPromote(location, version);
  // Command demote
  if (loose_values[0] == "demote")
    return CmdDemote(location, version);
  // Command revoke
  if (loose_values[0] == "revoke")
    return CmdRevoke(location, version);

  LOG(ERROR) << "Unknown command '" << loose_values[0] << "'.";
  PrintUsage();
  return false;
}

rw::KeysetReader* KeyczarTool::GetReader(
    const std::string& location,
    KeyEncryption key_enc_type,
    const std::string& key_enc_value) const {
  switch (location_type_) {
    case JSON_FILE:
      return GetJSONFileReader(location, key_enc_type, key_enc_value);
    default:
      NOTREACHED();
  }

  return NULL;
}

rw::KeysetWriter* KeyczarTool::GetWriter(
    const std::string& location,
    KeyEncryption key_enc_type,
    const std::string& key_enc_value) const {
  switch (location_type_) {
    case JSON_FILE:
      return GetJSONFileWriter(location, key_enc_type, key_enc_value);
    default:
      NOTREACHED();
  }

  return NULL;
}

rw::KeysetJSONFileReader* KeyczarTool::GetJSONFileReader(
    const std::string& location,
    KeyEncryption key_enc_type,
    const std::string& key_enc_value) const {
  scoped_ptr<rw::KeysetJSONFileReader> reader;
  scoped_ptr<Crypter> crypter;

  switch (key_enc_type) {
    case NONE: {
      reader.reset(new rw::KeysetJSONFileReader(location));
      break;
    }
    case CRYPTER: {
      crypter.reset(Crypter::Read(key_enc_value));
      if (crypter.get() == NULL)
        return NULL;
      reader.reset(new rw::KeysetEncryptedJSONFileReader(location,
                                                         crypter.release()));
      break;
    }
    case PBE: {
      reader.reset(new rw::KeysetPBEJSONFileReader(location, key_enc_value));
      break;
    }
    default: {
      NOTREACHED();
    }
  }
  return reader.release();
}

rw::KeysetJSONFileWriter* KeyczarTool::GetJSONFileWriter(
    const std::string& location,
    KeyEncryption key_enc_type,
    const std::string& key_enc_value) const {
  scoped_ptr<rw::KeysetJSONFileWriter> writer;
  scoped_ptr<Encrypter> encrypter;

  switch (key_enc_type) {
    case NONE: {
      writer.reset(new rw::KeysetJSONFileWriter(location));
      break;
    }
    case CRYPTER: {
      encrypter.reset(Encrypter::Read(key_enc_value));
      if (encrypter.get() == NULL)
        return NULL;
      writer.reset(new rw::KeysetEncryptedJSONFileWriter(location,
                                                         encrypter.release()));
      break;
    }
    case PBE: {
      writer.reset(new rw::KeysetPBEJSONFileWriter(location, key_enc_value));
      break;
    }
    default: {
      NOTREACHED();
    }
  }
  return writer.release();
}

}  // namespace keyczar_tool
}  // namespace keyczar
