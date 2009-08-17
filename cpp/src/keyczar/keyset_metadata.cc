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
#include <keyczar/keyset_metadata.h>

#include <keyczar/base/logging.h>
#include <keyczar/base/values.h>

namespace keyczar {

KeysetMetadata::KeyVersion::KeyVersion(int version_number,
                                       KeyStatus::Type key_status,
                                       bool exportable)
    : version_number_(version_number), key_status_(key_status),
      exportable_(exportable) {
  CHECK_GE(version_number, 0);
}

// static
KeysetMetadata::KeyVersion* KeysetMetadata::KeyVersion::CreateFromValue(
    const Value* root_version) {
  if (root_version == NULL || !root_version->IsType(Value::TYPE_DICTIONARY))
    return NULL;

  const DictionaryValue* version =
      static_cast<const DictionaryValue*>(root_version);

  int version_number;
  if (!version->GetInteger("versionNumber", &version_number))
    return NULL;

  std::string key_status_string;
  if (!version->GetString("status", &key_status_string))
    return NULL;
  const KeyStatus::Type key_status =
      KeyStatus::GetTypeFromName(key_status_string);
  if (key_status == KeyStatus::UNDEF)
    return NULL;

  bool exportable;
  if (!version->GetBoolean("exportable", &exportable))
    return NULL;

  return new KeysetMetadata::KeyVersion(version_number, key_status, exportable);
}

Value* KeysetMetadata::KeyVersion::GetValue() const {
  scoped_ptr<DictionaryValue> version(new DictionaryValue);
  if (version.get() == NULL)
    return NULL;

  if (!version->SetInteger("versionNumber", version_number()))
    return NULL;

  std::string key_status_name = KeyStatus::GetNameFromType(key_status());
  if (key_status_name.empty() ||
      !version->SetString("status", key_status_name))
    return NULL;

  if (!version->SetBoolean("exportable", exportable()))
    return NULL;

  return version.release();
}

KeysetMetadata::KeyVersion* KeysetMetadata::KeyVersion::Copy() const {
  return new KeysetMetadata::KeyVersion(version_number(),
                                        key_status(),
                                        exportable());
}

void KeysetMetadata::KeyVersion::set_version_number(int version_number) {
  CHECK_GT(version_number, 0);
  version_number_ = version_number;
}

void KeysetMetadata::KeyVersion::set_key_status(KeyStatus::Type key_status) {
  key_status_ = key_status;
}

KeysetMetadata::KeysetMetadata(const std::string& name, KeyType::Type key_type,
                               KeyPurpose::Type key_purpose, bool encrypted,
                               int next_key_version_number)
    : name_(name), key_type_(key_type), key_purpose_(key_purpose),
      encrypted_(encrypted), next_key_version_number_(next_key_version_number) {
  CHECK_GT(next_key_version_number_, 0);
}

// static
KeysetMetadata* KeysetMetadata::CreateFromValue(const Value* root_metadata) {
  if (root_metadata == NULL || !root_metadata->IsType(Value::TYPE_DICTIONARY))
    return NULL;
  const DictionaryValue* metadata =
      static_cast<const DictionaryValue*>(root_metadata);

  std::string name;
  if (!metadata->GetString("name", &name))
    return NULL;

  std::string key_type_string;
  if (!metadata->GetString("type", &key_type_string))
    return NULL;
  const KeyType::Type key_type =
      KeyType::GetTypeFromName(key_type_string);
  if (key_type == KeyType::UNDEF)
    return NULL;

  std::string key_purpose_string;
  if (!metadata->GetString("purpose", &key_purpose_string))
    return NULL;
  const KeyPurpose::Type key_purpose =
      KeyPurpose::GetTypeFromName(key_purpose_string);
  if (key_purpose == KeyPurpose::UNDEF)
    return NULL;

  bool encrypted;
  if (!metadata->GetBoolean("encrypted", &encrypted))
    return NULL;

  // In case where the medatada file doesn't have a 'nextKeyVersionNumber'
  // field (which happens when key set was created with previous releases;
  // it is necessary to determinate a valid next_key_version_number value.
  bool has_next_key_version_number = metadata->HasKey("nextKeyVersionNumber");
  int next_key_version_number = 1;
  if (has_next_key_version_number &&
      !metadata->GetInteger("nextKeyVersionNumber", &next_key_version_number))
    return NULL;

  // Instatiates keyset metadata and key versions and adds key versions to
  // metadata object.
  scoped_ptr<KeysetMetadata> keyset_metadata(new KeysetMetadata(
      name, key_type,
      key_purpose, encrypted,
      next_key_version_number));
  if (keyset_metadata.get() == NULL)
    return NULL;

  ListValue* key_versions = NULL;
  if (!metadata->GetList("versions", &key_versions))
    return NULL;

  for (ListValue::iterator version_iterator = key_versions->begin();
       version_iterator != key_versions->end(); ++version_iterator) {
    if (!(*version_iterator)->IsType(Value::TYPE_DICTIONARY))
      return NULL;

    scoped_refptr<KeysetMetadata::KeyVersion> key_version;
    key_version = KeysetMetadata::KeyVersion::CreateFromValue(
        *version_iterator);
    if (key_version == NULL)
      return NULL;

    if (!keyset_metadata->AddVersion(key_version))
      return NULL;

    if (!has_next_key_version_number &&
        key_version->version_number() >= next_key_version_number)
      next_key_version_number = key_version->version_number() + 1;
  }

  if (!has_next_key_version_number)
    keyset_metadata->set_next_key_version_number(next_key_version_number);

  return keyset_metadata.release();
}

Value* KeysetMetadata::GetValue(bool public_export) const {
  scoped_ptr<DictionaryValue> metadata(new DictionaryValue);
  if (metadata.get() == NULL)
    return NULL;

  if (!metadata->SetString("name", name()))
    return NULL;

  std::string key_type_name = KeyType::GetNameFromType(key_type());
  if (key_type_name.empty() ||
      !metadata->SetString("type", key_type_name))
    return NULL;

  std::string key_purpose_name = KeyPurpose::GetNameFromType(key_purpose());
  if (key_purpose_name.empty() ||
      !metadata->SetString("purpose", key_purpose_name))
    return NULL;

  if (!metadata->SetBoolean("encrypted", encrypted()))
    return NULL;

#ifndef COMPAT_KEYCZAR_06B
  if (!public_export)
    if (!metadata->SetInteger("nextKeyVersionNumber",
                              next_key_version_number()))
      return NULL;
#endif

  ListValue* versions = new ListValue;
  if (versions == NULL)
    return NULL;
  if (!metadata->Set("versions", versions))
    return NULL;

  for (KeyVersionMap::const_iterator iter = key_versions_map_.begin();
       iter != key_versions_map_.end(); ++iter)
    versions->Append((iter->second)->GetValue());

  return metadata.release();
}

bool KeysetMetadata::AddVersion(KeyVersion* key_version) {
  if (key_version == NULL)
    return false;

  if (key_version->version_number() == 0) {
    key_version->set_version_number(next_key_version_number());
    inc_next_key_version_number();
  }

  int version_number = key_version->version_number();
  if (key_versions_map_.find(version_number) != key_versions_map_.end())
    return false;

  key_versions_map_[version_number] = key_version;
  return true;
}

bool KeysetMetadata::RemoveVersion(int version_number) {
  KeyVersionMap::iterator iter = key_versions_map_.find(version_number);
  if (iter == key_versions_map_.end())
    return false;
  key_versions_map_.erase(iter);
  return true;
}

const KeysetMetadata::KeyVersion* KeysetMetadata::GetVersion(
    int version_number) const {
  KeyVersionMap::const_iterator iter = key_versions_map_.find(version_number);
  if (iter == key_versions_map_.end())
    return NULL;
  return iter->second;
}

KeysetMetadata::KeyVersion* KeysetMetadata::GetVersion(int version_number) {
  KeyVersionMap::iterator iter = key_versions_map_.find(version_number);
  if (iter == key_versions_map_.end())
    return NULL;
  return iter->second;
}

}  // namespace keyczar
