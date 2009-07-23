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
  static Key* CreateFromValue(const KeyType& key_type, const Value& root);

  // Factory to generate a key of type |key_type| and of length |size|. The
  // caller takes ownership of the returned Key. Returns NULL if |size| is
  // not valid or if it fails.
  static Key* GenerateKey(const KeyType& key_type, int size);

  // Factory to create a key of type |key_type| from a PEM key with location
  // |filename| and optional passphrase |passphrase|. If |passphrase| value
  // is NULL, it means no passphrase. This function returns NULL if it fails.
  // The caller takes ownership of the returned Key.
  static Key* CreateFromPEMKey(const KeyType& key_type,
                               const std::string& filename,
                               const std::string* passphrase);

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
  virtual bool Encrypt(const std::string& data, std::string* encrypted) const;

  // This method must be implemented by secret key subclasses and by some of
  // private key subclasses. This method returns false if it is not implemented
  // or if it fails.
  virtual bool Decrypt(const std::string& encrypted, std::string* data) const;

  // Returns the hash assembled from the values of various fields of this
  // instance. This hash will be used as unique identifier of this key.
  virtual bool Hash(std::string* hash) const = 0;

  static int GetHashSize();

  static int GetHeaderSize();

  static char GetVersionByte();

  // Returns header value.
  bool Header(std::string* header) const;

  // Returns the size in bits corresponding to this key.
  int size() const { return size_; }

 protected:
  // Helper function for building the Hash value. Be sure to have properly
  // initialized the message digest object before calling it the first time.
  void AddToHash(const std::string& field,
                 MessageDigestImpl& digest_impl) const;

 private:
  // Key size in bits
  int size_;

  DISALLOW_COPY_AND_ASSIGN(Key);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEY_H_
