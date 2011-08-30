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

#include <keyczar/base/basictypes.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/file_path.h>
#include <keyczar/key_purpose.h>
#include <keyczar/key_type.h>
#include <keyczar/keyset.h>

namespace keyczar {

class KeysetReader;

// High-level class for loading a key set and using it for encrypting /
// decrypting and signing / verifying data depending on the type and on the
// purpose of the loaded key set. Keys are automatically selected for each
// operations. Clients should access cryptographic operations through this
// interface. By default, all cryptographic operations returns web-safe base64
// encoded strings.  To get binary outputs, call
// set_encoding(Keyczar::NO_ENCODING).
//
// Inheritance tree:
//
//               /Keyczar/
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
  // Update the corresponding enum structure inside keyczar.i if this one
  // was modified.
  enum Encoding {
    NO_ENCODING,  // No encoding
    BASE64W       // Web-safe base64 encoding (used by default)
  };

  // Update the corresponding enum structure inside keyczar.i if this one
  // was modified.
  enum Compression {
    NO_COMPRESSION,  // No compression (used by default)
    GZIP,            // GZIP compression generally used when compressing files
    ZLIB             // Simple zlib compression
  };

  // This constructor takes ownership of the provided Keyset object |keyset|.
  // By default all the results are web-safe base64 encoded and all input
  // plaintext messages are not compressed.
  explicit Keyczar(Keyset* keyset)
      : keyset_(keyset), encoding_(BASE64W), compression_(NO_COMPRESSION) {}

  virtual ~Keyczar() {}

  // All the following methods must be implemented by the relevant subclasses.
  // Returning false if not implemented or in case of failure.

  // Signs the given input string |data| and put the result as a web-safe
  // Base64 encoded string into |signature|. This method uses the current
  // encoding format to encode the resulting signature. This method returns
  // false if it fails.
  virtual bool Sign(const std::string& data, std::string* signature) const;

  // Signs |data| and returns the signature as string value. This method
  // overloads the previous Sign method and internally calls it. It returns
  // an empty string if it fails.
  virtual std::string Sign(const std::string& data) const;

  // Sign the |data| and the |hidden| data.  Attach the signature to
  // the data and return that.  When the signature is verified, the
  // same hidden data must be provided.
  virtual bool AttachedSign(const std::string& data,
                            const std::string& hidden,
                            std::string* signed_data) const;

  // Signs the |data| and the |hidden| data and returns the signature
  // as a string value.  This method overloads the previous
  // AttachedSign method and internally calls it.  It returns an empty
  // string if it fails.
  virtual std::string AttachedSign(const std::string& data,
                                   const std::string& hidden) const;

  // Verifies the |signature| of the corresponding |data|. |signature| is
  // decoded accordingly to the current encoding algorithm set.
  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  // Verifies the |signed_data|, which contains both data and
  // signature and, if okay, extracts the |data|.  The signature is
  // assumed to have had the |hidden| data signed with the data during
  // signature generation.  The signature is decoded according to the
  // current encoding algorithm set.  It returns false if it fails.
  virtual bool AttachedVerify(const std::string& signed_data,
                              const std::string& hidden,
                              std::string* data) const;

  // Gets the signed data from |signed_data|, without verifying the
  // signature.  Returns true if extraction is successful.
  virtual bool GetAttachedWithoutVerify(const std::string& signed_data,
                                        std::string* data) const;

  // Encrypts the given input string |plaintext| and put the result as a
  // web-safe Base64 encoded string into |ciphertext|. This method uses the
  // current compression algorithm set to compress |plaintext| before encryption
  // and uses the current encoding algorithm set to encode the resulting
  // |ciphertext| (BASE64W by default). This method returns false if it fails.
  virtual bool Encrypt(const std::string& plaintext,
                       std::string* ciphertext) const;

  // Encrypts |plaintext| and returns the ciphertext as string value. This
  // method overloads the previous Encrypt method and internally calls it. This
  // method returns an empty string if it fails.
  virtual std::string Encrypt(const std::string& plaintext) const;

  // Decrypts web-safe Base64 encoded string |ciphertext| and writes the
  // decrypted plaintext into |plaintext|. It uses the current encoding
  // format to decode the |ciphertext| and the current format compression to
  // decompress the resulting |plaintext| after having decrypted it. This
  // method returns false if it fails.
  virtual bool Decrypt(const std::string& ciphertext,
                       std::string* plaintext) const;

  // Decrypts |ciphertext| and returns the plaintext as string value. This
  // method overloads the previous Encrypt method and internally calls it. This
  // method returns an empty string if it fails.
  virtual std::string Decrypt(const std::string& ciphertext) const;

  // Returns true if the operations implemented by this class can be applied to
  // the current keyset.
  virtual bool IsAcceptablePurpose() const = 0;

  // Returns the current encoding algorithm set.
  Encoding encoding() const { return encoding_; }

  // Replaces the current encoding algorithm by |encoding|.
  void set_encoding(Encoding encoding) { encoding_ = encoding; }

  // Returns the current compression algorithm set.
  Compression compression() const { return compression_; }

  // Replaces the current compression algorithm by |compression|.
  void set_compression(Compression compression) { compression_ = compression; }

  // Returns the Keyset instance.
  const Keyset* keyset() const { return keyset_.get(); }

 protected:
  KeyPurpose::Type GetKeyPurpose() const;
  KeyType::Type GetKeyType() const;

  bool GetHash(const std::string& bytes, std::string* hash) const;

  // Retrieves the current encoding format, encodes |input_value| and assigns
  // the result into |encoded_value|. Returns false if it fails.
  bool Encode(const std::string& input_value, std::string* encoded_value) const;

  // Retrieves the current encoding format, decodes |encoded_value| and assigns
  // the result into |decoded_value|. Returns false if it fails.
  bool Decode(const std::string& encoded_value,
              std::string* decoded_value) const;

  // Retrieves the current compression format, compresses |input| and put
  // the result into |output|. Returns false if it fails.
  bool Compress(const std::string& input, std::string* output) const;

  // Retrieves the current compression format, decompresses |input| and put
  // the result into |output|. Returns false if it fails.
  bool Decompress(const std::string& input, std::string* output) const;

  // Searches the current keyset for a key matching the hash in
  // |key_header|.  Returns NULL if there is no current keyset, or if
  // the hash cannot be found in the header, or if there is no key
  // matching the hash.  Note that |key_header| may contain additional
  // bytes beyond the header; any extra data will be ignored.
  const Key* LookupKey(const std::string& key_header) const;

 private:
  const scoped_ptr<Keyset> keyset_;

  // Encoding format used for representing cryptographic operations results. The
  // default encoding format used is BASE64W. It applies to encryption and
  // signatures operations.
  Encoding encoding_;

  // Compression format used to compress input plaintext or input data about
  // to be signed. The default compression mode is set to NO_COMPRESSION.
  // It applies to encryption operations.
  Compression compression_;

  DISALLOW_COPY_AND_ASSIGN(Keyczar);
};

// An Encrypter is exclusively used to encrypt data. Typically, Encrypters use
// symmetric keys to encrypt the provided data, although RSA public keys may
// also be used for encryption. However public keys are only able to encrypt
// limited sizes of data.
class Encrypter : public Keyczar {
 public:
  explicit Encrypter(Keyset* keyset) : Keyczar(keyset) {}

  // This factory returns a new Encrypter. This will attempt to read the keys
  // from |location| using a KeysetReader. The corresponding key set must
  // have as purpose: ENCRYPT or DECRYPT_AND_ENCRYPT.
  static Encrypter* Read(const std::string& location);

  static Encrypter* Read(const FilePath& location);

  // This factory returns a new Encrypter directly from a reader. This permit to
  // read key set from unconventionnal readers e.g. from an encrypted reader.
  static Encrypter* Read(const rw::KeysetReader& reader);

  virtual bool Encrypt(const std::string& plaintext,
                       std::string* ciphertext) const;

  virtual std::string Encrypt(const std::string& plaintext) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(Encrypter);
};

// A Crypter extends its base class Encrypter by providing a decryption
// method which then can be used with a secret symmetric key or a private
// RSA key to decrypt the data.
class Crypter : public Encrypter {
 public:
  explicit Crypter(Keyset* keyset) : Encrypter(keyset) {}

  // This factory returns a new Crypter. This will attempt to read the keys
  // from |location| using a KeysetReader. The corresponding key set must
  // have as purpose: DECRYPT_AND_ENCRYPT.
  static Crypter* Read(const std::string& location);

  static Crypter* Read(const FilePath& location);

  // This factory returns a new Crypter directly from a reader. This permit to
  // read key set from unconventionnal readers e.g. from an encrypted reader.
  static Crypter* Read(const rw::KeysetReader& reader);

  virtual bool Decrypt(const std::string& ciphertext,
                       std::string* plaintext) const;

  virtual std::string Decrypt(const std::string& ciphertext) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(Crypter);
};

// A Verifier is exclusively used to verify the validity of signatures. This
// class can be instanciated with a symmetric HMAC key or with an asymmetric
// key.
class Verifier : public Keyczar {
 public:
  explicit Verifier(Keyset* keyset) : Keyczar(keyset) {}

  // This factory returns a new Verifier. This will attempt to read the
  // keys from |location| using a KeysetReader. The corresponding key set
  // must have as purpose: VERIFY or SIGN_AND_VERIFY.
  static Verifier* Read(const std::string& location);

  static Verifier* Read(const FilePath& location);

  // This factory returns a new Verifier directly from a reader. This permit to
  // read key set from unconventionnal readers.
  static Verifier* Read(const rw::KeysetReader& reader);

  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  virtual bool AttachedVerify(const std::string& signed_data,
                              const std::string& hidden,
                              std::string* data) const;

  virtual bool GetAttachedWithoutVerify(const std::string& signed_data,
                                        std::string* data) const {
    return ParseAttachedSignature(signed_data, NULL, data, NULL);
  }

  virtual bool IsAcceptablePurpose() const;

 protected:
  // Constructs a message ready for signing (or signature verification)
  std::string BuildMessageToSign(const std::string& data,
                                 const std::string* hidden) const;

 private:
  // Verifies that |signature| is a correct signature on |verification_data|
  // using the key described by |key_header|.  Note that key_header may
  // contain additional data after the header; any additional bytes will
  // be ignored.
  bool InternalVerify(const std::string& verification_data,
                      const std::string& key_header,
                      const std::string& signature) const;

  // Parses the key header, data and signature from an attached
  // signature.  If any output argument is NULL, it will be ignored,
  // so this method can be used to extract whichever pieces are
  // desired.
  bool ParseAttachedSignature(const std::string& signed_data,
                              std::string* header,
                              std::string* data,
                              std::string* signature) const;

  DISALLOW_COPY_AND_ASSIGN(Verifier);
};

// Unversioned Verifiers are exclusively used to verify standard signatures
// (i.e. HMAC, DSA, ECDSA, RSA) with no key version information.
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
  // must have as purpose: VERIFY or SIGN_AND_VERIFY.
  static UnversionedVerifier* Read(const std::string& location);

  static UnversionedVerifier* Read(const FilePath& location);

  // This factory returns a new UnversionedVerifier directly from a reader. This
  // permit to read key set from unconventionnal readers.
  static UnversionedVerifier* Read(const rw::KeysetReader& reader);

  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnversionedVerifier);
};

// A Signer may both sign and verify data using a symmetric or private
// key.
//
// Signer objects should be used with symmetric or private key sets to
// generate signatures.
class Signer : public Verifier {
  typedef Verifier super;

 public:
  explicit Signer(Keyset* keyset) : Verifier(keyset) {}

  // This factory returns a new Signer. This will attempt to read the keys
  // from |location| using a KeysetReader. The corresponding key set must
  // have as purpose: SIGN_AND_VERIFY.
  static Signer* Read(const std::string& location);

  static Signer* Read(const FilePath& location);

  // This factory returns a new Signer directly from a reader. This permit to
  // read key set from unconventionnal readers.
  static Signer* Read(const rw::KeysetReader& reader);

  virtual bool Sign(const std::string& data, std::string* signature) const;

  virtual std::string Sign(const std::string& data) const;

  virtual bool AttachedSign(const std::string& data,
                            const std::string& hidden,
                            std::string* signed_data) const;

  virtual std::string AttachedSign(const std::string& data,
                                   const std::string& hidden) const {
    return super::AttachedSign(data, hidden);
  }

  virtual bool IsAcceptablePurpose() const;

 private:
  // Signs |data| and |hidden| (if not NULL) and writes the resulting
  // signature bytes into |signature| and the key header (needed to
  // construct the output message) into |key_header|.
  bool InternalSign(const std::string& data, const std::string* hidden,
                    std::string* signature, std::string* key_header) const ;

  DISALLOW_COPY_AND_ASSIGN(Signer);
};

// An UnversionedSigner may both sign and verify data using a symmetric or
// private key. A public key may only be used with Verifier objects.
//
// UnversionedSigners do not include any key versioning in their outputs. They
// will return standard signatures (i.e. HMAC, RSA, DSA, ECDSA).
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
  // permit to read key set from unconventionnal readers.
  static UnversionedSigner* Read(const rw::KeysetReader& reader);

  virtual bool Sign(const std::string& data, std::string* signature) const;

  virtual std::string Sign(const std::string& data) const;

  virtual bool IsAcceptablePurpose() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnversionedSigner);
};

}  // namespace keyczar

#endif  // KEYCZAR_KEYCZAR_H_
