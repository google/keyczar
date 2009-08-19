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
#ifndef KEYCZAR_KEYCZAR_TOOL_KEYCZAR_TOOL_H_
#define KEYCZAR_KEYCZAR_TOOL_KEYCZAR_TOOL_H_

#include <string>

#include <keyczar/base/basictypes.h>
#include <keyczar/base/command_line.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/key_purpose.h>
#include <keyczar/key_status.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_reader.h>
#include <keyczar/rw/keyset_writer.h>

namespace keyczar {
namespace keyczar_tool {

// Class used by keyczart for processing the command line and executing
// the appropriate commands.
class KeyczarTool {
 public:
  // Update the corresponding enum structure inside keyczar.i if this one
  // was modified.
  enum LocationType {
    // Locations represent directories/files/others medias containing metadata
    // and keys files.
    JSON_FILE     // Use JSON files as key set
  };

  // Update the corresponding enum structure inside keyczar.i if this one
  // was modified.
  enum KeyEncryption {
    NONE,     // No key encryption
    CRYPTER,  // Use another key set for encrypting this key
    PBE       // Password-based encryption
  };

  // Update the corresponding enum structure inside keyczar.i if this one
  // was modified.
  enum Cipher {
    SYMMETRIC,
    DSA,
    ECDSA,
    RSA
  };

  // |location_type| is used for instanciating the right reader and writer
  // when a key set is loaded or has to be written.
  explicit KeyczarTool(LocationType location_type)
      : location_type_(location_type) {}

  // Processes command lines arguments |argv| and writes results to
  // |location_type|. This method returns false if it failed.
  static bool ProcessCommandLine(LocationType location_type, int argc,
                                 char** argv);

  // |location| is the path/file location of the key set. |name| is the name
  // of the new created key set. |cipher| is the key set's cipher type and
  // |key_purpose| designates the purpose assigned to this key set.
  //
  // Python examples:
  // >>> import keyczar
  // >>> kt = keyczar.KeyczarTool(keyczar.KeyczarTool.JSON_FILE)
  // >>> kt.CmdCreate("/path/aes", keyczar.KeyPurpose.DECRYPT_AND_ENCRYPT,
  //                  "Test", keyczar.KeyczarTool.SYMMETRIC)
  // or
  // >>> kt.CmdCreate("/path/rsa", keyczar.KeyPurpose.DECRYPT_AND_ENCRYPT,
  //                  "Test", keyczar.KeyczarTool.RSA)
  bool CmdCreate(const std::string& location, KeyPurpose::Type key_purpose,
                 const std::string& name, Cipher cipher) const;

  // |location| is the path/file location of the key set. |size| is the key
  // size in bits, if |size| is equal to 0 the default size for this cipher
  // will be used. If |key_enc_type| is PBE and |key_enc_value| is empty
  // a password will be prompted interactively. If |key_enc_type| is not NONE
  // and if this is the first key added to the underlying key set then its
  // "encrypted" flag will be set to true and it will only be possible to add
  // encrypted keys after that operation (or the lifetime of this key set). If
  // this key set already have keys |key_enc_type| must be compatible with its
  // settings. If |key_enc_type| is equal to NONE or CRYPTER then
  // |key_enc_value| is not considered. This method returns 0 on error or its
  // assigned key version number otherwise.
  //
  // Python examples:
  // >>> kt.CmdAddKey("/path/aes", keyczar.KeyStatus.PRIMARY, 0,
  //                  keyczar.KeyczarTool.NONE, "")
  // or
  // >>> kt.CmdAddKey("/path/rsa", keyczar.KeyStatus.PRIMARY, 0,
  //                  keyczar.KeyczarTool.PBE, "")
  // Enter PBE password: <use 'cartman' as password>
  int CmdAddKey(const std::string& location, KeyStatus::Type key_status,
                int size, KeyEncryption key_enc_type,
                const std::string& key_enc_value) const;

  // Imports private key |filename| to |location| key set with status |status|.
  // |passphrase| is used to decrypt and read |filename|. |key_enc_type| and
  // |key_enc_value| must match the settings of the key set |location| and will
  // be used to encrypt (or not) the imported key into |location|. This method
  // returns 0 if an error happened or its assigned key version number
  // otherwise. Currently it only can import private keys therefore |public_key|
  // must always be false;
  //
  // Python example:
  // >>> kt.CmdImportKey("/path/rsa", keyczar.KeyStatus.PRIMARY,
  //                     "/src/keyczar/data/rsa_pem/rsa_priv_encrypted.pem",
  //                     "cartman", keyczar.KeyczarTool.PBE, "", False)
  // openssl rsa -in /path/rsa_priv.pem -text -passin pass:cartman
  int CmdImportKey(const std::string& location, KeyStatus::Type key_status,
                   const std::string& filename, const std::string* passphrase,
                   KeyEncryption key_enc_type,
                   const std::string& key_enc_value, bool public_key) const;

  // Exports the current primary private key from |location| to |filename|.
  // The private key is encrypted with |passphrase| and its export format is
  // PKCS8. This method returns false if there is no primary key, if it is a
  // public key or if it fails. Currently it only can import private keys
  // therefore |public_key| must always be false. |key_enc_type| and
  // |key_enc_value| are used for reading the key set (for more details see
  // previous commands).
  //
  // Python example:
  // kt.CmdExportKey("/path/rsa", "/path/rsa_priv.pem", "cartman",
  //                 keyczar.KeyczarTool.PBE, "", False)
  bool CmdExportKey(const std::string& location, const std::string& filename,
                    const std::string* passphrase, KeyEncryption key_enc_type,
                    const std::string& key_enc_value, bool public_key) const;

  // Extracts and exports to |destination| the public key associated to each
  // private key embedded into key set |location|. |key_enc_type| and
  // |key_enc_value| are used for reading private keys from |location|.
  //
  // Python example:
  // >>> kt.CmdPubKey("/path/rsa", "/path/rsa_pub", keyczar.KeyczarTool.PBE,
  //                  "cartman")
  bool CmdPubKey(const std::string& location, const std::string& destination,
                 KeyEncryption key_enc_type,
                 const std::string& key_enc_value) const;

  // Python example:
  // >>> kt.CmdPromote("/path/rsa", 1)
  bool CmdPromote(const std::string& location, int version) const;

  // Python example:
  // >>> kt.CmdDemote("/path/rsa", 2)
  bool CmdDemote(const std::string& location, int version) const;

  // Python example:
  // >>> kt.CmdRevoke("/path/rsa", 2)
  bool CmdRevoke(const std::string& location, int version) const;

  // Replaces |location_type_| by |location_type|.
  void set_location_type(LocationType location_type);

 private:
  // This method processes the provided command line arguments and calls
  // each corresponding Cmd<command> commands along with the required arguments.
  // It returns false if it failed.
  bool DoProcessCommandLine(const base::CommandLine& cmdl);

  // Factory method returns a reader object. The Reader's class is determined
  // by the value of |location_type_|.
  rw::KeysetReader* GetReader(const std::string& location,
                              KeyEncryption key_enc_type,
                              const std::string& key_enc_value) const;

  // Factory method returns a writer object. The Writer's class is determined
  // by the value of |location_type_|.
  rw::KeysetWriter* GetWriter(const std::string& location,
                              KeyEncryption key_enc_type,
                              const std::string& key_enc_value) const;

  rw::KeysetJSONFileReader* GetJSONFileReader(
      const std::string& location,
      KeyEncryption key_enc_type,
      const std::string& key_enc_value) const;

  rw::KeysetJSONFileWriter* GetJSONFileWriter(
      const std::string& location,
      KeyEncryption key_enc_type,
      const std::string& key_enc_value) const;

  // Will be used to decide which reader and writer to instanciate.
  LocationType location_type_;

  scoped_ptr<base::CommandLine> command_line_;

  DISALLOW_COPY_AND_ASSIGN(KeyczarTool);
};

}  // namespace keyczar_tool
}  // namespace keyczar

#endif  // KEYCZAR_KEYCZAR_TOOL_KEYCZAR_TOOL_H_
