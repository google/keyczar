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
#ifndef KEYCZAR_KEYSET_METADATA_H_
#define KEYCZAR_KEYSET_METADATA_H_

#include <string>
#include <map>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>
#include <keyczar/key_purpose.h>
#include <keyczar/key_status.h>
#include <keyczar/key_type.h>

namespace keyczar {

// This class represents a key set metadata in memory.
class KeysetMetadata {
 public:
  class KeyVersion : public base::RefCounted<KeysetMetadata::KeyVersion> {
   public:
    // If this object is not instanciated from CreateFromValue you likely should
    // pass 0 as |version_number|. In this case a correct version number will be
    // assigned later automatically when this object will be inserted into a
    // metadata's map of key versions. If you decide to pass a non-zero value
    // this version number will be left unchanged.
    KeyVersion(int version_number, KeyStatus::Type key_status, bool exportable);

    // Creates a KeyVersion from a Value tree |root_version|. Usually
    // |root_version| is built from a JSON representation. The caller takes
    // ownership of the result.
    static KeyVersion* CreateFromValue(const Value* root_version);

    // A Value composite is assembled and returned from the data members
    // contained in this class. The caller takes ownership of the result.
    Value* GetValue() const;

    // Copy |this| key version.
    KeyVersion* Copy() const;

    int version_number() const { return version_number_; }

    // Sets a new strictly positive |version_number|.
    void set_version_number(int version_number);

    // Replaces the previous key status.
    void set_key_status(KeyStatus::Type key_status);

    KeyStatus::Type key_status() const { return key_status_; }

    bool exportable() const { return exportable_; }

   private:
    // Key version number.
    int version_number_;

    // Current status of the key.
    KeyStatus::Type key_status_;

    // Set to true if the key is exportable.
    bool exportable_;

    DISALLOW_COPY_AND_ASSIGN(KeyVersion);
  };

  typedef std::map<int, scoped_refptr<KeyVersion> > KeyVersionMap;

  // Custom iterators.
  typedef KeyVersionMap::iterator iterator;
  typedef KeyVersionMap::const_iterator const_iterator;

  // Usually a good |next_key_version_number| for a new empty metadata is 1.
  KeysetMetadata(const std::string& name, KeyType::Type key_type,
                 KeyPurpose::Type key_purpose, bool encrypted,
                 int next_key_version_number);

  // Creates a KeysetMetadata from a Value tree |root_version|. Usually
  // |root_version| is built from a JSON representation. The caller takes
  // ownership of the result.
  static KeysetMetadata* CreateFromValue(const Value* root_metadata);

  // A Value composite is assembled and returned from the data members
  // contained in this class. The caller takes ownership of the result.
  // If |public_export| is set to true the field |nextKeyVersionNumber|
  // is not added to this composite. This is useful for example in the
  // case of public key export where the keyset won't receive any new key
  // version.
  Value* GetValue(bool public_export) const;

  // Key versions operations.

  // Takes ownership over |key_version| and adds it indexed by its key version
  // number to the map of key versions. If necessary (see the constructor of
  // KeyVersion) the next key version number's value is assigned to the
  // corresponding field in |key_version|. Returns false if it failed.
  bool AddVersion(KeyVersion* key_version);

  // Returns true if the KeyVersion object indexed by |version_number| is
  // sucessfully removed from the map of key versions. Its object is deleted.
  bool RemoveVersion(int version_number);

  // Returns the object indexed by |version_number|. The caller doesn't take
  // ownership of the returned KeyVersion object. Returns NULL if no key
  // versions corresponds to |version_number|.
  const KeyVersion* GetVersion(int version_number) const;

  KeyVersion* GetVersion(int version_number);

  // Accessors.

  std::string name() const { return name_; }

  KeyType::Type key_type() const { return key_type_; }

  KeyPurpose::Type key_purpose() const { return key_purpose_; }

  bool encrypted() const { return encrypted_; }

  void set_encrypted(bool encrypted) { encrypted_ = encrypted; }

  // Returns the next key version number. This number should be used when
  // a new key is added to the key set.
  int next_key_version_number() const { return next_key_version_number_; }

  void set_next_key_version_number(int number) {
    next_key_version_number_ = number;
  }

  // Allow iteration over the map of key versions using STL iterators. The
  // iterator's |first| will be the version number, and the iterator's
  // |second| will be a pointer to a KeyVersion.
  const_iterator Begin() const { return key_versions_map_.begin(); }
  iterator Begin() { return key_versions_map_.begin(); }
  const_iterator End() const { return key_versions_map_.end(); }
  iterator End() { return key_versions_map_.end(); }

  // Returns true if the metadata has no key versions.
  bool Empty() const { return key_versions_map_.empty(); }

 private:
  // Increments key version number.
  void inc_next_key_version_number() { ++next_key_version_number_; }

  // Key set's name.
  std::string name_;

  // Type of the keys stored into this key set.
  KeyType::Type key_type_;

  // Purpose of the keys stored into this key set.
  KeyPurpose::Type key_purpose_;

  // Set to true if keys of this set must be encrypted.
  bool encrypted_;

  // Next key version number
  int next_key_version_number_;

  // Indexes the key versions of the underlying key set by their key version
  // number. This class will manage its KeyVersion instances and will release it
  // automatically.
  KeyVersionMap key_versions_map_;

  DISALLOW_COPY_AND_ASSIGN(KeysetMetadata);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_METADATA_H_
