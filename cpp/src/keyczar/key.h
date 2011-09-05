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
#ifndef KEYCZAR_KEY_H_
#define KEYCZAR_KEY_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/ref_counted.h>
#include <keyczar/base/values.h>
#include <keyczar/key_type.h>

namespace keyczar {

class MessageDigestImpl;

// Keys are represented by this class. Keys must be managed through
// scoped_refptr. There are two factory methods for instanciating keys:
// CreateFromValue and GenerateKey. The first one permits to deserialize
// an existing key, the second one creates a new key using the underlying
// concrete cryptographic library.
//
// Current inheritance hierarchy:
//
//                               /Key/
//                                 ^
//                                 |
//       ---------------------------------------------------
//      |         |          |                              |
//      |         |          |                              |
//  SecretKey  HMACKey   PrivateKey                     PublicKey
//      ^                    ^                              ^
//      |                    |                              |
//      |        -----------------------            --------------------
//   AESKey     |            |          |          |        |           |
//         DSAPrivateKey     |    RSAPrivateKey    |    ECDSAPublicKey  |
//                   ECDSAPrivateKey           DSAPublicKey        RSAPublicKey
//
//
// Each key aggregates a concrete implementation through an abstract interface
// and delegates all the cryptographic operations to this object. See this
// design applied to the class AESKey:
//
//  AESKey <>----> AESImpl
//                   ^
//                   |
//  --------------------------- OpenSSL ---
//                   |
//               AESOpenSSL
//
// The concrete objects are instanciated through the CryptoFactory class.
//
class Key : public base::RefCounted<Key> {
 public:
Key(int size) : size_(size) {}
  virtual ~Key() {}

  // Factory to create a key of type |key_type| with value |root|. The
  // caller takes ownership of the returned Key.
  static Key* CreateFromValue(KeyType::Type key_type, const Value& root);

  // Factory to generate a key of type |key_type| and of length |size|. The
  // caller takes ownership of the returned Key. Returns NULL if |size| is
  // not valid or if it fails.
  static Key* GenerateKey(KeyType::Type key_type, int size);

  // Factory to create a key of type |key_type| from a PEM/PKCS8 key located
  // at |filename|. |passphrase| is an optional passphrase, its value is NULL
  // if no passphrase is expected or if it should be prompted interactively at
  // execution. The caller takes ownership over the returned object. This
  // method can handle PEM format keys as well as PKCS8 format keys. It returns
  // NULL if it fails.
  static Key* CreateFromPEMPrivateKey(KeyType::Type key_type,
                                      const std::string& filename,
                                      const std::string* passphrase);

  // Exports this key encrypted with |passphrase| to |filename|. The format
  // used is PKCS8 and the key is encrypted with PBE algorithm as defined in
  // PKCS5 v2.0, the associated cipher used is AES. If |passphrase| is NULL
  // a callback function will be called to prompt a passphrase at execution.
  // It returns false if it fails.
  virtual bool ExportPrivateKey(const std::string& filename,
                                const std::string* passphrase) const;

  // Build a Value object from the key attributes and returns the result.
  // The caller takes ownership of the returned instance. It returns NULL
  // if it fails.
  virtual Value* GetValue() const = 0;

  // This method must be implemented by private key subclasses. This method
  // returns NULL if it is not implemented or if it fails. The caller takes
  // ownership of the returned object.
  virtual Value* GetPublicKeyValue() const;

  // Cryptographic operations.

  // This method must be implemented by private key subclasses. This method
  // returns false if it is not implemented or if it fails.
  virtual bool Sign(const std::string& data, std::string* signature) const;

  // This method must be implemented by public key subclasses. This method
  // returns false if it is not implemented or if it fails.
  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  // This method must be implemented by secret key subclasses and by some of
  // private key subclasses. This method returns false if it is not implemented
  // or if it fails.
  virtual bool Encrypt(const std::string& plaintext,
                       std::string* ciphertext) const;

  // This method must be implemented by secret key subclasses and by some of
  // private key subclasses. This method returns false if it is not implemented
  // or if it fails.
  virtual bool Decrypt(const std::string& ciphertext,
                       std::string* plaintext) const;

  // Returns the hash assembled from the values of various fields of this
  // instance. This hash will be used as unique identifier of this key.
  virtual bool Hash(std::string* hash) const = 0;

  // Returns an additional "buggy" hash which some messages encrypted by
  // previous versions of Keyczar may use to reference this key.  Returns
  // false if no buggy hash exists (only AES keys with leading zero bytes
  // had buggy hashes).
  virtual bool BuggyHash(std::string* buggy_hash) const;

  static int GetHashSize();

  static int GetHeaderSize();

  static char GetVersionByte();

  // Returns header value.
  bool Header(std::string* header) const;

  // Returns the size in bits corresponding to this key.
  int size() const { return size_; }

 protected:
  // Helper function for building the Hash value. If |trim_zeros| is true,
  // any leading zeros in |field| will first be removed.  Be sure to have
  // properly initialized the message digest object before calling it the
  // first time.
  void AddToHash(const std::string& field,
                 MessageDigestImpl& digest_impl,
                 bool trim_zeros = true) const;

 private:
  // Key size in bits
  int size_;

  DISALLOW_COPY_AND_ASSIGN(Key);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEY_H_
