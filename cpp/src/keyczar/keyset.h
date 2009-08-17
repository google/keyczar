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
#ifndef KEYCZAR_KEYSET_H_
#define KEYCZAR_KEYSET_H_

#include <map>
#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/observer_list.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/key.h>
#include <keyczar/keyset_metadata.h>

namespace keyczar {

namespace rw {
class KeysetReader;
class KeysetWriter;
}  // namespace rw

// A key set manages a set of metadata and keys. At its creation a Keyset is
// empty. Before any action, an Observer must be added in the case where this
// Keyset must be stored on disk (for example). After that, an initial
// KeysetMetadata object must be inserted. Then eventually, keys can safely be
// generated and added to this set. Observers are notified each time the
// metadata is updated, keys are added or revoked.
//
//  Keyset <>-1------> KeysetMetadata
//         <>-0,n----> Key
//
// Example:
//
//  namespace keyczar {
//
//  Keyset keyset;
//  rw::KeysetJSONFileWriter file_writer(path);
//  keyset.AddObserver(&file_writer);
//
//  KeysetMetadata* meta = NULL;
//  meta = new KeysetMetadata("Test",  // name
//                            KeyType::RSA_PRIV,  // type
//                            KeyPurpose::DECRYPT_AND_ENCRYPT,  // purpose
//                            false,  // encrypted
//                            1);  // next version number
//
//  keyset.set_metadata(meta);
//  keyset.GenerateKey(KeyStatus::PRIMARY, 2048);
//
//  }  // namespace keyczar
class Keyset {
 public:
  class Observer {
   public:
    Observer() {}
    virtual ~Observer() {}

    // This method is called each time |key_metadata| is updated.
    virtual void OnUpdatedKeysetMetadata(
        const KeysetMetadata& key_metadata) = 0;

    // This method is called each time a new key |key| is added to the keyset.
    virtual void OnNewKey(const Key& key, int version_number) = 0;

    // This method is called each time a key from the keyset is revoked.
    virtual void OnRevokedKey(int version_number) = 0;
  };

  // STL map used for associating |Key| to version numbers.
  typedef std::map<int, scoped_refptr<Key> > VersionNumberMap;

  // Custom iterators.
  typedef VersionNumberMap::iterator iterator;
  typedef VersionNumberMap::const_iterator const_iterator;

  // Instantiates an empty key set. By default |primary_key_index_| must
  // be set to 0, it means that there is currently no PRIMARY key in the set.
  Keyset() : metadata_(NULL), primary_key_version_number_(0) {}

  // Factory method for instanciating a new Keyset instance from |reader|. The
  // |reader| is used for reading existing metadata and keys. The caller takes
  // ownership over the returned object. If |load_keys| is false the keys are
  // not loaded in this keyset, for more explanations read comment of
  // ReadMetadataOnly below. This factory returns NULL if it fails. During this
  // function there is no possibility for observers to be notified. Therefore
  // the initial state set up will be missed. The observers will only be
  // notified of the subsequent modifications once the keyset will be returned
  // and the observers added.
  static Keyset* Read(const rw::KeysetReader& reader, bool load_keys);

  // Instanciates a new Keyset object without loading its associated keys. The
  // only operations authorized in this mode are the operations modifying the
  // metadata. Do not manipulate keys in this mode. The intent of this mode is
  // to bypass key decryption by not loading them. For instance it is convenient
  // for calls to promotekey, Demotekey. Note that RevokeKey still calls
  // OnRevokedKey() for each one of its observers.
  static Keyset* ReadMetadataOnly(const rw::KeysetReader& reader);

  // The caller keeps ownership over |obs|.
  void AddObserver(Observer* obs) {
    observer_list_.AddObserver(obs);
  }

  void RemoveObserver(Observer* obs) {
    observer_list_.RemoveObserver(obs);
  }

  void NotifyOnUpdatedKeysetMetadata(const KeysetMetadata& metadata) const {
    FOR_EACH_OBSERVER(Observer, observer_list_,
                      OnUpdatedKeysetMetadata(metadata));
  }

  void NotifyOnNewKey(const Key& key, int version_number) const {
    FOR_EACH_OBSERVER(Observer, observer_list_,
                      OnNewKey(key, version_number));
  }

  void NotifyOnRevokedKey(int version_number) const {
    FOR_EACH_OBSERVER(Observer, observer_list_,
                      OnRevokedKey(version_number));
  }

  // The Keyset object keeps the ownership of returned result. The metadata
  // should never be modified outside of the functions provided by this class
  // because otherwise the observers would not be notified of the changes.
  const KeysetMetadata* metadata() const { return metadata_.get(); }

  // Sets a new |metadata|. This instance takes ownership of |metadata|.
  void set_metadata(KeysetMetadata* metadata);

  // Modifies the corresponding field of the metadata. |encrypted| is true
  // when all key versions are encrypted and must be read with an encrypted
  // reader.
  void set_encrypted(bool encrypted);

  // This object keeps the ownership of returned key. It returns NULL if
  // no key was indexed with |version_number|.
  const Key* GetKey(int version_number) const;

  const Key* GetKeyFromHash(const std::string& hash) const;

  // This object keeps the ownership of the returned Key object. It returns
  // NULL if there is no primary key yet.
  const Key* primary_key() const;

  // Returns the version number of the current primary key.
  int primary_key_version_number() const { return primary_key_version_number_; }

  // Returns current primary key version from |metadata_| object.
  const KeysetMetadata::KeyVersion* GetPrimaryKeyVersion() const;
  KeysetMetadata::KeyVersion* GetPrimaryKeyVersion();

  // Maps |key| with |version_number| as index into |version_number_map_| and
  // maps the hash corresponding to |key| with |key| into |hash_map_|. It must
  // already exists a key version in the |metadata_| object associated with this
  // version number. Moreover no other key must have been previously associated
  // with this key version. This function takes ownership of |key|. This method
  // returns false if |key| couldn't be added.
  bool AddKey(Key* key, int version_number);

  // Generates a new key. First, a new key version is built with |status| as key
  // status and with |exportable| sets to |false|. This key version is added to
  // the list of key versions contained into the metadata. Then, a new key is
  // generated its size is |size| and its type depends on the informations
  // provided by the corresponding metadata. Once the key is generated |AddKey|
  // is called to store this new key. This function returns the newly assigned
  // key version number. This method returns 0 in case of failure.
  int GenerateKey(KeyStatus::Type status, int size);

  // Generates a key with a default size specified by its type and with |status|
  // as status. This method returns 0 if an error happened or its assigned key
  // version number otherwise.
  int GenerateDefaultKeySize(KeyStatus::Type status);

  // Imports a PEM/PKCS8 key with |status| as status at location |filename| on
  // disk and with asscociated passphrase |passphrase|. A NULL value for
  // |passphrase| means no passphrase. If a passphrase is required anyway to
  // read this key, it will be prompted interactively. This method returns 0
  // if an error happened or its assigned key version number otherwise.
  int ImportPrivateKey(KeyStatus::Type status, const std::string& filename,
                       const std::string* passphrase);

  // Exports current primary private key to |filename|. |passphrase| is used to
  // encrypt the key with PBE algorithm. Its format is PKCS8 and it returns
  // false if there is no primary key, if this is a public key or if it fails.
  bool ExportPrivateKey(const std::string& filename,
                        const std::string* passphrase);

  // Operations on keys.

  // Promotes key |version_number|. INACTIVE keys become ACTIVE and ACTIVE keys
  // become PRIMARY. In this latter case, if a key was already set to PRIMARY,
  // it is automatically demoted to ACTIVE. It can be only one PRIMARY key at
  // a given time.
  bool PromoteKey(int version_number);

  // Demotes key |version_number|. ACTIVE keys become INACTIVE and PRIMARY keys
  // become ACTIVE. Already INACTIVE keys are left INACTIVE. If a PRIMARY key is
  // demoted, the caller will then have to promote a new PRIMARY key before
  // performing cryptographic operations.
  bool DemoteKey(int version_number);

  // When a key is revoked its informations are removed from the metadata of its
  // keyset and its key can be erased from its storage support depending on the
  // KeysetWriter used.
  bool RevokeKey(int version_number);

  // If relevant, that is if the keyset instance manages private keys and has a
  // compatible puporse then the public parts of these keys are exported with
  // |writer|.
  bool PublicKeyExport(const rw::KeysetWriter& writer) const;

  // Allow iteration over the map of version numbers and keys using STL
  // iterators. The iterator's member |first| points on the version number, and
  // the iterator's member |second| points on a Key.
  const_iterator Begin() const { return version_number_map_.begin(); }
  iterator Begin() { return version_number_map_.begin(); }
  const_iterator End() const { return version_number_map_.end(); }
  iterator End() { return version_number_map_.end(); }

  // Returns true if the key set contains no keys.
  bool Empty() const;

 private:
  // STL map used for associating |Key| to string hashes.
  typedef std::map<std::string, scoped_refptr<Key> > HashMap;

  void set_primary_key_version_number(int version_number) {
    primary_key_version_number_ = version_number;
  }

  // Returns false if status update failed.
  bool UpdateKeyStatus(KeyStatus::Type new_status,
                       KeysetMetadata::KeyVersion* key_version);

  // Helper function for removing a key designated by its |version_number| from
  // |hash_map_| and from |version_number_map_|. Returns false if it failed.
  bool RemoveKey(int version_number);

  // Adds |key_version| to |metadata_| object. This function also assigns a
  // version number and returns it. This class takes ownership of |key_version|.
  // It returns 0 if |key_version| insertion failed.
  int AddKeyVersion(KeysetMetadata::KeyVersion* key_version);

  // Removes key version |version_number| from |metadata_| object. It returns
  // true if it succeeds. This call is expected to always succeed.
  bool RemoveKeyVersion(int version_number);

  // Holds metadata associated to this set.
  scoped_ptr<KeysetMetadata> metadata_;

  // This is the version number of the current primary key. This value can
  // be used as index for retrieving the primary key into the container
  // |version_number_map_|. This attribute holds 0 when no primary key isn't
  // actually set.
  int primary_key_version_number_;

  // Indexes each key by its unique version number provided through its
  // associated metadata.
  VersionNumberMap version_number_map_;

  // Indexes each key by its unique hash calculated from internal its fields.
  // Indexed keys are shared with |version_number_map_| and their references are
  // counted.
  HashMap hash_map_;

  // List of observers notified when modifications on metadata and keys
  // happened.
  ObserverList<Observer> observer_list_;

  DISALLOW_COPY_AND_ASSIGN(Keyset);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYSET_H_
