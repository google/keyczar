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
#ifndef KEYCZAR_KEYCZAR_H_
#define KEYCZAR_KEYCZAR_H_

#include <string>

#include "base/basictypes.h"
#include "base/scoped_ptr.h"
#include "base/file_path.h"

#include "keyczar/keyset.h"

namespace keyczar {

class KeyPurpose;
class KeysetReader;

// High-level class for loading a key set and using it for encrypting /
// decrypting and signing / verifying data depending on the type and on the
// purpose of the loaded key set. Keys are automatically selected for each
// operations. Clients should access cryptographic operations through this
// interface.
//
// Inheritance tree:
//
//                Keyczar
//                   ^
//                   |
//       -------------------------
//      |            |            |
//      |            |            |
//      |            |            |
//  Encrypter     Verifier    UnversionedVerifier
//      ^            ^            ^
//      |            |            |
//      |            |            |
//   Crypter       Signer     UnversionedSigner
//
//
// Example: encrypting and decrypting data.
//
//   namespace keyczar {
//
//   Keyczar* encrypter = Encrypter::Read(location);
//   std::string ciphertext;
//   if (!encrypter || !encrypter->Encrypt("Secret message.", &ciphertext))
//      std::cerr << "Cannot encrypt data" << std::endl;
//   delete encrypter;
//
//   Keyczar* crypter = Crypter::Read(location));
//   std::string plaintext;
//   if (!crypter || !crypter->Decrypt(ciphertext, &plaintext))
//      std::cerr << "Cannot decrypt data" << std::endl;
//   delete crypter;
//
//   }  // namespace keyczar
//
class Keyczar {
 public:
  // This constructor takes ownership of the provided Keyset object |keyset|.
  explicit Keyczar(Keyset* keyset) : keyset_(keyset) {}

  virtual ~Keyczar() {}

  // This method must be implemented by signers subclasses. It returns
  // false if it is not implemented or if it fails.
  virtual bool Sign(const std::string& data, std::string* signature) const;

  // This method must be implemented by signers subclasses. It returns an
  // empty string if it is not implemented or if it fails.
  virtual std::string Sign(const std::string& data) const;

  // This method must be implemented by verifiers subclasses. It returns
  // false if it is not implemented or if it fails.
  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  // This method must be implemented by encrypters subclasses. It returns
  // false if it is not implemented or if it fails.
  virtual bool Encrypt(const std::string& data, std::string* ciphertext) const;

  // This method must be implemented by encrypters subclasses. It returns an
  // empty string if it is not implemented or if it fails.
  virtual std::string Encrypt(const std::string& data) const;

  // This method must be implemented by crypters subclasses. It returns
  // false if it is not implemented or if it fails.
  virtual bool Decrypt(const std::string& ciphertext, std::string* data) const;

  // This method must be implemented by crypters subclasses. It returns an
  // empty string if it is not implemented or if it fails.
  virtual std::string Decrypt(const std::string& ciphertext) const;

  // Returns true if the operations implemented by this class can be applied to
  // the current keyset.
  virtual bool IsAcceptablePurpose() const = 0;

  // Returns the Keyset instance.
  const Keyset* keyset() const { return keyset_.get(); }

 protected:
  const KeyPurpose* GetKeyPurpose() const;

  bool GetHash(const std::string& bytes, std::string* hash) const;

 private:
  const scoped_ptr<Keyset> keyset_;

  DISALLOW_COPY_AND_ASSIGN(Keyczar);
};

// Encrypters are used strictly to encrypt data. Typically, Encrypters will read
// sets of public keys, although may also be instantiated with sets of symmetric
// keys. Crypter objects should be used with symmetric or private key sets to
// decrypt data.
class Encrypter : public Keyczar {
 public:
  explicit Encrypter(Keyset* keyset) : Keyczar(keyset) {}

  // This factory returns a new Crypter. This will attempt to read the keys
  // from |location| using a KeysetReader. The corresponding key set must
  // have a purpose of ENCRYPT or DECRYPT_AND_ENCRYPT.
  static Encrypter* Read(const std::string& location);

  static Encrypter* Read(const FilePath& location);

  // This factory returns a new Encrypter directly from a reader. This permit to
  // read key set from unconventionnal readers e.g. from an encrypted reader.
  static Encrypter* Read(const KeysetReader& reader);

  // Encrypts the given input string |data| and put the result as a web-safe
  // Base64 encoded string into |ciphertext|. This method returns false if it
  // fails.
  virtual bool Encrypt(const std::string& data, std::string* ciphertext) const;

  // Encrypts |data| and returns the ciphertext as string value. Returns an
  // empty string if it fails.
  virtual std::string Encrypt(const std::string& data) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(Encrypter);
};

// Crypters may both encrypt and decrypt data using sets of symmetric or private
// keys. Sets of public keys may only be used with Encrypter objects.
class Crypter : public Encrypter {
 public:
  explicit Crypter(Keyset* keyset) : Encrypter(keyset) {}

  // This factory returns a new Crypter. This will attempt to read the keys
  // from |location| using a KeysetReader. The corresponding key set must
  // have a purpose of DECRYPT_AND_ENCRYPT.
  static Crypter* Read(const std::string& location);

  static Crypter* Read(const FilePath& location);

  // This factory returns a new Crypter directly from a reader. This permit to
  // read key set from unconventionnal readers e.g. from an encrypted reader.
  static Crypter* Read(const KeysetReader& reader);

  // Decrypts the web-safe Base64 encoded string |ciphertext| and write the
  // decrypted plaintext into |data|. This method returns false if it fails.
  virtual bool Decrypt(const std::string& ciphertext, std::string* data) const;

  // Decrypts |ciphertext| and returns the plaintext as string value. Returns
  // an empty string if it fails.
  virtual std::string Decrypt(const std::string& ciphertext) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(Crypter);
};

// Verifiers are used strictly to verify signatures. Typically, Verifiers will
// read sets of public keys, although may also be instantiated with sets of
// symmetric or private keys. Signer objects should be used with symmetric or
// private key sets to generate signatures.
class Verifier : public Keyczar {
 public:
  explicit Verifier(Keyset* keyset) : Keyczar(keyset) {}

  // This factory returns a new Verifier. This will attempt to read the
  // keys from |location| using a KeysetReader. The corresponding key set
  // must have a purpose of VERIFY or SIGN_AND_VERIFY.
  static Verifier* Read(const std::string& location);

  static Verifier* Read(const FilePath& location);

  // This factory returns a new Verifier directly from a reader. This permit to
  // read key set from unconventionnal readers e.g. from an encrypted reader.
  static Verifier* Read(const KeysetReader& reader);

  // Verifies the |signature| on the given |data|.
  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(Verifier);
};

// Unversioned Verifiers are used strictly to verify standard signatures
// (i.e. HMAC-SHA1, DSA-SHA1, RSA-SHA1) with no key version information.
// Typically, UnversionedVerifiers will read sets of public keys, although may
// also be instantiated with sets of symmetric or private keys.
//
// Since UnversionedVerifiers verify standard signatures, they will try all keys
// in a set until one verifies.
//
// UnversionedSigner objects should be used with symmetric or private
// key sets to generate unversioned signatures.
class UnversionedVerifier : public Keyczar {
 public:
  explicit UnversionedVerifier(Keyset* keyset) : Keyczar(keyset) {}

  // This factory returns a new UnversionedVerifier. This will attempt to read
  // the keys from |location| using a KeysetReader. The corresponding key set
  // must have a purpose of VERIFY or SIGN_AND_VERIFY.
  static UnversionedVerifier* Read(const std::string& location);

  static UnversionedVerifier* Read(const FilePath& location);

  // This factory returns a new UnversionedVerifier directly from a reader. This
  // permit to read key set from unconventionnal readers e.g. from an encrypted
  // reader.
  static UnversionedVerifier* Read(const KeysetReader& reader);

  // Verifies the |signature| on the given |data|.
  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnversionedVerifier);
};

// Signers may both sign and verify data using sets of symmetric or private
// keys. Sets of public keys may only be used with Verifier objects.
//
// Signer objects should be used with symmetric or private key sets to
// generate signatures.
class Signer : public Verifier {
 public:
  explicit Signer(Keyset* keyset) : Verifier(keyset) {}

  // This factory returns a new Signer. This will attempt to read the keys
  // from |location| using a KeysetReader. The corresponding key set must
  // have a purpose of SIGN_AND_VERIFY.
  static Signer* Read(const std::string& location);

  static Signer* Read(const FilePath& location);

  // This factory returns a new Signer directly from a reader. This permit to
  // read key set from unconventionnal readers e.g. from an encrypted reader.
  static Signer* Read(const KeysetReader& reader);

  // Signs the given input string |data| and put the result as a web-safe
  // Base64 encoded string into |signature|. This method returns false if it
  // fails.
  virtual bool Sign(const std::string& data, std::string* signature) const;

  // Signs |data| and returns the signature as string value. It returns an
  // empty string if it fails.
  virtual std::string Sign(const std::string& data) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(Signer);
};

// UnversionedSigners may both sign and verify data using sets of symmetric or
// private keys. Sets of public keys may only be used with Verifier
// objects.
//
// UnversionedSigners do not include any key versioning in their outputs. They
// will return standard signatures (i.e. HMAC-SHA1, RSA-SHA1, DSA-SHA1).
//
// UnversionedSigner objects should be used with symmetric or private key sets
// to generate signatures.
class UnversionedSigner : public UnversionedVerifier {
 public:
  explicit UnversionedSigner(Keyset* keyset) : UnversionedVerifier(keyset) {}

  // This factory returns a new UnversionedSigner. This will attempt to read the
  // keys from |location| using a KeysetReader. The corresponding key set must
  // have a purpose of SIGN_AND_VERIFY.
  static UnversionedSigner* Read(const std::string& location);

  static UnversionedSigner* Read(const FilePath& location);

  // This factory returns a new UnversionedSigner directly from a reader. This
  // permit to read key set from unconventionnal readers e.g. from an encrypted
  // reader.
  static UnversionedSigner* Read(const KeysetReader& reader);

  // Signs the given input string |data| and put the result as a web-safe
  // Base64 encoded string into |signature|. This method returns false if it
  // fails.
  virtual bool Sign(const std::string& data, std::string* signature) const;

  // Signs |data| and returns the signature as string value. It returns an
  // empty string if it fails.
  virtual std::string Sign(const std::string& data) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnversionedSigner);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYCZAR_H_
