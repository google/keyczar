%module keyczar
%{
#include <keyczar/keyczar.h>
#include <keyczar/keyset_reader.h>
#include <keyczar/keyset_file_reader.h>
#include <keyczar/keyset_encrypted_file_reader.h>
%}

%include "std_string.i"

namespace keyczar {

class Crypter;

class KeysetReader {
 public:
  virtual ~KeysetReader() = 0;
};

class KeysetJSONFileReader : public KeysetReader {
 public:
  KeysetJSONFileReader(const std::string& location);
};

class KeysetEncryptedJSONFileReader : public KeysetJSONFileReader {
 public:
  KeysetEncryptedJSONFileReader(const std::string& location,
                                Crypter* crypter);
};

class Keyczar {
 public:
  enum Encoding {
    NO_ENCODING,
    BASE64W
  };

  enum Compression {
    NO_COMPRESSION,
    GZIP,
    ZLIB
  };

  virtual ~Keyczar() = 0;

  virtual std::string Sign(const std::string& data) const;
  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;
  virtual std::string Encrypt(const std::string& plaintext) const;
  virtual std::string Decrypt(const std::string& ciphertext) const;

  Encoding encoding() const;
  void set_encoding(Encoding encoding);

  Compression compression() const;
  void set_compression(Compression compression);
};

%nodefaultctor Encrypter;
class Encrypter : public Keyczar {
 public:
  static Encrypter* Read(const std::string& location);
  static Encrypter* Read(const KeysetReader& reader);

  virtual std::string Encrypt(const std::string& plaintext) const;
};

%nodefaultctor Crypter;
class Crypter : public Encrypter {
 public:
  static Crypter* Read(const std::string& location);
  static Crypter* Read(const KeysetReader& reader);

  virtual std::string Decrypt(const std::string& ciphertext) const;
};

%nodefaultctor Verifier;
class Verifier : public Keyczar {
 public:
  static Verifier* Read(const std::string& location);
  static Verifier* Read(const KeysetReader& reader);

  virtual bool Verify(const std::string& data,
  	              const std::string& signature) const;
};

%nodefaultctor UnversionedVerifier;
class UnversionedVerifier : public Keyczar {
 public:
  static UnversionedVerifier* Read(const std::string& location);
  static UnversionedVerifier* Read(const KeysetReader& reader);

  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;
};

%nodefaultctor Signer;
class Signer : public Verifier {
 public:
  static Signer* Read(const std::string& location);
  static Signer* Read(const KeysetReader& reader);

  virtual std::string Sign(const std::string& data) const;
};

%nodefaultctor UnversionedSigner;
class UnversionedSigner : public Verifier {
 public:
  static UnversionedSigner* Read(const std::string& location);
  static UnversionedSigner* Read(const KeysetReader& reader);

  virtual std::string Sign(const std::string& data) const;
};

}  // namespace keyczar
