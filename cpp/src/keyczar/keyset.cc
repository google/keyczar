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
#include <keyczar/keyset.h>

#include <keyczar/base/logging.h>
#include <keyczar/key.h>
#include <keyczar/rw/keyset_reader.h>
#include <keyczar/rw/keyset_writer.h>

namespace keyczar {

// static
Keyset* Keyset::Read(const rw::KeysetReader& reader, bool load_keys) {
  // Instantiates empty key set
  scoped_ptr<Keyset> keyset(new Keyset());
  if (keyset.get() == NULL)
    return NULL;

  // Read metadata and insert into key set
  scoped_ptr<Value> root_metadata(reader.ReadMetadata());
  if (root_metadata.get() == NULL)
    return NULL;

  KeysetMetadata* metadata = KeysetMetadata::CreateFromValue(
      root_metadata.get());
  if (metadata == NULL)
    return NULL;
  keyset->set_metadata(metadata);

  const KeyType::Type key_type = metadata->key_type();
  if (key_type == KeyType::UNDEF)
    return NULL;

  // Iterates over metadata, read keys and insert them into keyset.
  KeysetMetadata::const_iterator version_iterator = metadata->Begin();
  for (; version_iterator != metadata->End(); ++version_iterator) {
    int version_number = version_iterator->first;

    if (load_keys) {
      scoped_ptr<Value> root_key(reader.ReadKey(version_number));
      if (root_key.get() == NULL)
        return NULL;

      scoped_refptr<Key> key = Key::CreateFromValue(key_type, *root_key);
      if (key == NULL)
        return NULL;

      if (!keyset->AddKey(key, version_number))
        return NULL;
    }

    if (version_iterator->second == NULL)
      return NULL;

    if (version_iterator->second->key_status() == KeyStatus::PRIMARY) {
      if (keyset->primary_key_version_number() > 0) {
        LOG(WARNING) << "Keyset cannot have more than one primary key";
        return NULL;
      }
      keyset->set_primary_key_version_number(version_number);
    }
  }

  return keyset.release();
}

// static
Keyset* Keyset::ReadMetadataOnly(const rw::KeysetReader& reader) {
  return Keyset::Read(reader, false);
}

void Keyset::set_metadata(KeysetMetadata* metadata) {
  metadata_.reset(metadata);
  if (metadata_.get())
    NotifyOnUpdatedKeysetMetadata(*metadata_.get());
}

void Keyset::set_encrypted(bool encrypted) {
  if (metadata_.get() == NULL)
    return;

  metadata_->set_encrypted(encrypted);
  NotifyOnUpdatedKeysetMetadata(*metadata_.get());
}

const Key* Keyset::GetKey(int version_number) const {
  VersionNumberMap::const_iterator iter = version_number_map_.find(
      version_number);
  if (iter == version_number_map_.end())
    return NULL;
  return iter->second;
}

const Key* Keyset::GetKeyFromHash(const std::string& hash) const {
  HashMap::const_iterator iter = hash_map_.find(hash);
  if (iter == hash_map_.end())
    return NULL;
  return iter->second;
}

const Key* Keyset::primary_key() const {
  return GetKey(primary_key_version_number());
}

const KeysetMetadata::KeyVersion* Keyset::GetPrimaryKeyVersion() const {
  if (metadata_.get() == NULL)
    return NULL;
  return metadata_->GetVersion(primary_key_version_number());
}

KeysetMetadata::KeyVersion* Keyset::GetPrimaryKeyVersion() {
  if (metadata_.get() == NULL)
    return NULL;
  return metadata_->GetVersion(primary_key_version_number());
}

bool Keyset::AddKey(Key* key, int version_number) {
  if (key == NULL || version_number <= 0 || metadata_.get() == NULL ||
      metadata_->GetVersion(version_number) == NULL ||
      version_number_map_.find(version_number) != version_number_map_.end())
    return false;

  std::string hash;
  if (!key->Hash(&hash))
    return false;

  if (hash_map_.find(hash) != hash_map_.end()) {
    LOG(ERROR) << "A key set cannot have multiple identical keys.";
    return false;
  }

  version_number_map_[version_number] = key;
  hash_map_[hash] = key;

  if (key->BuggyHash(&hash)) {
      hash_map_[hash] = key;
  }

  NotifyOnNewKey(*key, version_number);
  return true;
}

int Keyset::GenerateKey(KeyStatus::Type status, int size) {
  if (metadata_.get() == NULL)
    return 0;

  const KeyType::Type key_type = metadata_->key_type();
  if (key_type == KeyType::UNDEF)
    return 0;

  scoped_refptr<Key> key;
  std::string hash;
  do {
    key = Key::GenerateKey(key_type, size);
    if (key == NULL)
      return 0;

    if (!key->Hash(&hash))
      return 0;
  } while (hash_map_.find(hash) != hash_map_.end());

  if (status == KeyStatus::PRIMARY && primary_key_version_number() > 0 &&
      !DemoteKey(primary_key_version_number()))
    return 0;

  scoped_refptr<KeysetMetadata::KeyVersion> key_version;
  key_version =  new KeysetMetadata::KeyVersion(0, status, false);
  if (key_version == NULL)
    return 0;

  int version_number = AddKeyVersion(key_version);
  if (version_number == 0)
    return 0;

  if (!AddKey(key, version_number)) {
    DCHECK(RemoveKeyVersion(version_number));
    return 0;
  }

  return version_number;
}

int Keyset::GenerateDefaultKeySize(KeyStatus::Type status) {
  if (metadata_.get() == NULL)
    return 0;

  const KeyType::Type key_type = metadata_->key_type();
  if (key_type == KeyType::UNDEF)
    return 0;

  return GenerateKey(status, KeyType::DefaultCipherSize(key_type));
}

int Keyset::ImportPrivateKey(KeyStatus::Type status,
                             const std::string& filename,
                             const std::string* passphrase) {
  if (metadata_.get() == NULL)
    return 0;

  const KeyType::Type key_type = metadata_->key_type();
  if (key_type == KeyType::UNDEF)
    return 0;

  scoped_refptr<Key> key = Key::CreateFromPEMPrivateKey(key_type, filename,
                                                        passphrase);
  if (key == NULL)
    return 0;

  std::string hash;
  if (!key->Hash(&hash))
    return 0;

  if (hash_map_.find(hash) != hash_map_.end()) {
    LOG(ERROR) << "This key is already in the key set.";
    return 0;
  }

  if (status == KeyStatus::PRIMARY && primary_key_version_number() > 0 &&
      !DemoteKey(primary_key_version_number()))
    return 0;

  scoped_refptr<KeysetMetadata::KeyVersion> key_version;
  key_version =  new KeysetMetadata::KeyVersion(0, status, false);
  if (key_version == NULL)
    return 0;

  int version_number = AddKeyVersion(key_version);
  if (version_number == 0)
    return 0;

  if (!AddKey(key, version_number)) {
    DCHECK(RemoveKeyVersion(version_number));
    return 0;
  }

  return version_number;
}

bool Keyset::ExportPrivateKey(const std::string& filename,
                              const std::string* passphrase) {
  const Key* key = primary_key();
  if (key == NULL) {
    LOG(INFO) << "Export failed:  No primary key";
    return false;
  }

  if (!key->ExportPrivateKey(filename, passphrase))
    LOG(INFO) << "Failed to export key of type "
               << KeyType::GetNameFromType(metadata()->key_type());
}

bool Keyset::PromoteKey(int version_number) {
  if (version_number <= 0 || metadata_.get() == NULL ||
      metadata_->GetVersion(version_number) == NULL)
    return false;

  KeysetMetadata::KeyVersion* key_version = metadata_->GetVersion(
      version_number);
  if (!key_version)
    return false;

  switch (key_version->key_status()) {
    case KeyStatus::PRIMARY:
      LOG(WARNING) << "Cannot promote a primary key.";
      return false;
    case KeyStatus::ACTIVE:
      return UpdateKeyStatus(KeyStatus::PRIMARY, key_version);
    case KeyStatus::INACTIVE:
      return UpdateKeyStatus(KeyStatus::ACTIVE, key_version);
    default:
      NOTREACHED();
  }
  return false;
}

bool Keyset::DemoteKey(int version_number) {
  if (version_number <= 0 || metadata_.get() == NULL ||
      metadata_->GetVersion(version_number) == NULL)
    return false;

  KeysetMetadata::KeyVersion* key_version = metadata_->GetVersion(
      version_number);
  if (!key_version)
    return false;

  switch (key_version->key_status()) {
    case KeyStatus::PRIMARY:
      if (UpdateKeyStatus(KeyStatus::ACTIVE, key_version))
        set_primary_key_version_number(0);  // no more PRIMARY keys in the set
      return true;
    case KeyStatus::ACTIVE:
      return UpdateKeyStatus(KeyStatus::INACTIVE, key_version);
    case KeyStatus::INACTIVE:
      LOG(WARNING) << "Cannot demote an inactive key.";
      return false;
    default:
      NOTREACHED();
  }
  return false;
}

bool Keyset::RevokeKey(int version_number) {
  if (version_number <= 0 || metadata_.get() == NULL ||
      metadata_->GetVersion(version_number) == NULL)
    return false;

  KeysetMetadata::KeyVersion* key_version = metadata_->GetVersion(
      version_number);
  if (!key_version)
    return false;

  if (key_version->key_status() != KeyStatus::INACTIVE) {
    LOG(WARNING) << "Cannot revoke an active key.";
    return false;
  }

  // Remove key version and key
  CHECK(RemoveKeyVersion(version_number));
  // There is one case where this call can fail, it is when the key set has
  // been instanciated through ReadMetadataOnly. Thus, the return value is
  // ignored and NotifyOnRevokedKey is always called. The consistency is
  // primarly based on the metadata so this is not wrong to do so.
  RemoveKey(version_number);
  NotifyOnRevokedKey(version_number);
  return true;
}

bool Keyset::PublicKeyExport(const rw::KeysetWriter& writer) const {
  if (metadata() == NULL)
    return false;

  const KeyType::Type key_type = metadata()->key_type();
  const KeyPurpose::Type key_purpose = metadata()->key_purpose();
  if (key_type == KeyType::UNDEF || key_purpose == KeyPurpose::UNDEF)
    return false;

  scoped_ptr<KeysetMetadata> meta;
  switch (key_type) {
    case KeyType::DSA_PRIV:
      if (key_purpose == KeyPurpose::SIGN_AND_VERIFY) {
        meta.reset(new KeysetMetadata(metadata()->name(),
                                      KeyType::DSA_PUB,
                                      KeyPurpose::VERIFY,
                                      false,
                                      metadata()->next_key_version_number()));
      } else {
        NOTREACHED();
        return false;
      }
      break;
    case KeyType::ECDSA_PRIV:
      if (key_purpose == KeyPurpose::SIGN_AND_VERIFY) {
        meta.reset(new KeysetMetadata(metadata()->name(),
                                      KeyType::ECDSA_PUB,
                                      KeyPurpose::VERIFY,
                                      false,
                                      metadata()->next_key_version_number()));
      } else {
        NOTREACHED();
        return false;
      }
      break;
    case KeyType::RSA_PRIV:
      if (key_purpose == KeyPurpose::DECRYPT_AND_ENCRYPT) {
        meta.reset(new KeysetMetadata(metadata()->name(),
                                      KeyType::RSA_PUB,
                                      KeyPurpose::ENCRYPT,
                                      false,
                                      metadata()->next_key_version_number()));
      } else {
        if (key_purpose == KeyPurpose::SIGN_AND_VERIFY) {
          meta.reset(new KeysetMetadata(metadata()->name(),
                                        KeyType::RSA_PUB,
                                        KeyPurpose::VERIFY,
                                        false,
                                        metadata()->next_key_version_number()));
        } else {
          NOTREACHED();
          return false;
        }
      }
      break;
    default:
      LOG(ERROR) << "Key type "
                 << KeyType::GetNameFromType(key_type)
                 << " cannot be exported.";
      NOTREACHED();
      return false;
  }

  if (meta.get() == NULL)
    return false;

  // Iterates over key versions, copy them, insert them inside |meta|,
  // for each retrieve the associated key, get its public component and
  // write it.
  KeysetMetadata::const_iterator version_iterator = metadata()->Begin();
  for (; version_iterator != metadata()->End(); ++version_iterator) {
    KeysetMetadata::KeyVersion* version_copy = version_iterator->second->Copy();
    if (version_copy == NULL)
      return false;
    if (!meta->AddVersion(version_copy))
      return false;

    int version_number = version_iterator->first;
    VersionNumberMap::const_iterator key_iterator = version_number_map_.find(
        version_number);
    if (key_iterator == version_number_map_.end())
      return false;

    scoped_ptr<Value> public_key_value(
        key_iterator->second->GetPublicKeyValue());
    if (public_key_value.get() == NULL ||
        !writer.WriteKey(*public_key_value, version_number))
      return false;
  }

  // It is important to write the metadata only after the keys because
  // key versions are agglomerated during the previous step.
  scoped_ptr<Value> metadata_value(meta->GetValue(true));
  if (metadata_value.get() == NULL)
    return false;
  if (!writer.WriteMetadata(*metadata_value))
    return false;

  return true;
}

bool Keyset::Empty() const {
  return hash_map_.empty() && version_number_map_.empty();
}

bool Keyset::UpdateKeyStatus(KeyStatus::Type new_status,
                             KeysetMetadata::KeyVersion* key_version) {
  if (key_version == NULL || metadata_.get() == NULL)
    return false;

  KeysetMetadata::KeyVersion* former_primary = GetPrimaryKeyVersion();

  switch (new_status) {
    case KeyStatus::PRIMARY:
      if (primary_key_version_number() != 0 && former_primary == NULL)
         return false;
      // Demotes current PRIMARY key, only one PRIMARY key at a given time
      if (former_primary != NULL)
        UpdateKeyStatus(KeyStatus::ACTIVE, former_primary);
      set_primary_key_version_number(key_version->version_number());
    case KeyStatus::ACTIVE:
    case KeyStatus::INACTIVE:
      key_version->set_key_status(new_status);
      NotifyOnUpdatedKeysetMetadata(*metadata_.get());
      return true;
    default:
      NOTREACHED();
  }
  return false;
}

bool Keyset::RemoveKey(int version_number) {
  VersionNumberMap::iterator version_iterator = version_number_map_.find(
      version_number);
  if (version_iterator == version_number_map_.end())
    return false;

  std::string hash;
  if (!version_iterator->second->Hash(&hash))
    return false;

  HashMap::iterator hash_iterator = hash_map_.find(hash);
  if (hash_iterator == hash_map_.end())
    return false;

  version_number_map_.erase(version_iterator);
  hash_map_.erase(hash_iterator);
  return true;
}

int Keyset::AddKeyVersion(KeysetMetadata::KeyVersion* key_version) {
  if (key_version ==  NULL || key_version->version_number() != 0 ||
      metadata_.get() == NULL)
    return 0;

  if (!metadata_->AddVersion(key_version))
    return 0;

  if (key_version->key_status() == KeyStatus::PRIMARY)
    CHECK(UpdateKeyStatus(KeyStatus::PRIMARY, key_version));

  NotifyOnUpdatedKeysetMetadata(*metadata_.get());
  return key_version->version_number();
}

bool Keyset::RemoveKeyVersion(int version_number) {
  if (version_number <= 0 || metadata_.get() == NULL ||
      metadata_->GetVersion(version_number) == NULL)
    return false;

  KeysetMetadata::KeyVersion* key_version = metadata_->GetVersion(
      version_number);
  if (!key_version)
    return false;

  // Remove key version
  if (!metadata_->RemoveVersion(version_number))
    return false;

  // Notify observers
  NotifyOnUpdatedKeysetMetadata(*metadata_.get());

  return true;
}

}  // namespace keyczar
