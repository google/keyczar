# -*- mode: c++; -*-
%module keyczar
%{
#include <keyczar/key_purpose.h>
#include <keyczar/key_status.h>
#include <keyczar/keyczar_tool/keyczar_tool.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_reader.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
%}

%include "std_string.i"

namespace keyczar {

class Crypter;

namespace rw {

class KeysetReader {
 public:
  virtual ~KeysetReader() = 0;
};

class KeysetJSONFileReader : public KeysetReader {
 public:
  KeysetJSONFileReader(const std::string& location);
};

class KeysetPBEJSONFileReader : public KeysetJSONFileReader {
 public:
  KeysetPBEJSONFileReader(const std::string& location,
              		  const std::string& password);
};

class KeysetEncryptedJSONFileReader : public KeysetJSONFileReader {
 public:
  KeysetEncryptedJSONFileReader(const std::string& location,
                                Crypter* crypter);
};

}  // namespace rw

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
  static Encrypter* Read(const rw::KeysetReader& reader);

  virtual std::string Encrypt(const std::string& plaintext) const;
};

%nodefaultctor Crypter;
class Crypter : public Encrypter {
 public:
  static Crypter* Read(const std::string& location);
  static Crypter* Read(const rw::KeysetReader& reader);

  virtual std::string Decrypt(const std::string& ciphertext) const;
};

%nodefaultctor Verifier;
class Verifier : public Keyczar {
 public:
  static Verifier* Read(const std::string& location);
  static Verifier* Read(const rw::KeysetReader& reader);

  virtual bool Verify(const std::string& data,
  	              const std::string& signature) const;
};

%nodefaultctor UnversionedVerifier;
class UnversionedVerifier : public Keyczar {
 public:
  static UnversionedVerifier* Read(const std::string& location);
  static UnversionedVerifier* Read(const rw::KeysetReader& reader);

  virtual bool Verify(const std::string& data,
                      const std::string& signature) const;
};

%nodefaultctor Signer;
class Signer : public Verifier {
 public:
  static Signer* Read(const std::string& location);
  static Signer* Read(const rw::KeysetReader& reader);

  virtual std::string Sign(const std::string& data) const;
};

%nodefaultctor UnversionedSigner;
class UnversionedSigner : public Verifier {
 public:
  static UnversionedSigner* Read(const std::string& location);
  static UnversionedSigner* Read(const rw::KeysetReader& reader);

  virtual std::string Sign(const std::string& data) const;
};

%nodefaultctor KeyPurpose;
class KeyPurpose {
 public:
  enum Type {
    // Does not expose UNDEF
    DECRYPT_AND_ENCRYPT = 1,
    ENCRYPT,
    SIGN_AND_VERIFY,
    VERIFY
  };
};

%nodefaultctor KeyStatus;
class KeyStatus {
 public:
  enum Type {
    // Does not expose UNDEF
    PRIMARY = 1,
    ACTIVE,
    INACTIVE
  };
};

namespace keyczar_tool {

class KeyczarTool {
 public:
  enum LocationType {
    JSON_FILE,
  };

  enum KeyEncryption {
    NONE,
    CRYPTER,
    PBE
  };

  enum Cipher {
    SYMMETRIC,
    DSA,
    ECDSA,
    RSA
  };

  explicit KeyczarTool(LocationType location_type);

  bool CmdCreate(const std::string& location, KeyPurpose::Type key_purpose,
                 const std::string& name, Cipher cipher) const;

  int CmdAddKey(const std::string& location, KeyStatus::Type key_status,
                int size, KeyEncryption key_enc_type,
                const std::string& key_enc_value) const;

%extend {
  // These methods are the same than the originals except a null pointer
  // is not accepted for the passphrase argument. That means that the
  // passphrase cannot be prompted interactively.

  int CmdImportKey(const std::string& location, KeyStatus::Type key_status,
                   const std::string& filename, const std::string passphrase,
                   KeyEncryption key_enc_type,
                   const std::string& key_enc_value, bool public_key) const {
      return self->CmdImportKey(location, key_status, filename, &passphrase,
                                key_enc_type, key_enc_value, public_key);
  }

  bool CmdExportKey(const std::string& location, const std::string& filename,
                    const std::string passphrase, KeyEncryption key_enc_type,
                    const std::string& key_enc_value, bool public_key) const {
    return self->CmdExportKey(location, filename, &passphrase,
                              key_enc_type, key_enc_value, public_key);
  }
}

  bool CmdPubKey(const std::string& location, const std::string& destination,
                 KeyEncryption key_enc_type,
                 const std::string& key_enc_value) const;

  bool CmdPromote(const std::string& location, int version) const;

  bool CmdDemote(const std::string& location, int version) const;

  bool CmdRevoke(const std::string& location, int version) const;

  void set_location_type(LocationType location_type);
};

}  // namespace keyczar_tool

}  // namespace keyczar
