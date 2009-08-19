// Demonstrates use of KeyczarTool commands.
//
// Usage: ./keyczar_tool /path/rsa_empty_path /path/rsa_pub_empty_path
//
#include <iostream>
#include <string>

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/key_purpose.h>
#include <keyczar/key_status.h>
#include <keyczar/keyczar_tool/keyczar_tool.h>

using namespace keyczar;
using namespace keyczar::base;
using namespace keyczar::keyczar_tool;

int RunCmds(const std::string& rsa_path, const std::string& rsa_pub_path) {
  ScopedSafeString password(new std::string("cartman"));

  scoped_ptr<KeyczarTool> kz_tool(new KeyczarTool(KeyczarTool::JSON_FILE));
  if (kz_tool.get() == NULL)
    return 1;

  // Creates a new RSA key set with signing purpose.
  if (!kz_tool->CmdCreate(
          rsa_path,
          KeyPurpose::SIGN_AND_VERIFY,  // key set purpose
          "MyRSASigner",                // key set name
          KeyczarTool::RSA)) {                     // asymmetric cipher type
    std::cerr << "Command 'create' failed." << std::endl;
    return 1;
  }

  const KeyczarTool::KeyEncryption pbe_encryption = KeyczarTool::PBE;

  // Adds a first 'active' key to this key set. This key will be encrypted
  // and the 'encrypted' flag of this key set will be set to true. That means
  // after that operation it will only be possible to add encrypted keys to
  // this key set.
  const int key1_version = kz_tool->CmdAddKey(
      rsa_path,
      KeyStatus::ACTIVE, // key status
      0,                 // use default cipher size
      pbe_encryption,    // key encryption type
      *password);
  if (key1_version <= 0) {
    std::cerr << "Command 'addkey' failed." << std::endl;
    return 1;
  }

  // Adds a second key to this key set.
  if (kz_tool->CmdAddKey(rsa_path, KeyStatus::ACTIVE, 0, pbe_encryption,
                         *password) <= 0) {
    std::cerr << "Command 'addkey' failed." << std::endl;
    return 1;
  }

  // Promotes the first key to primary
  if (!kz_tool->CmdPromote(rsa_path, key1_version)) {
    std::cerr << "Command 'promote' failed." << std::endl;
    return 1;
  }

  // Exports
  if (!kz_tool->CmdPubKey(rsa_path, rsa_pub_path, pbe_encryption, *password)) {
    std::cerr << "Command 'pubkey' failed." << std::endl;
    return 1;
  }

  std::cout << "Successfully executed all commands!" << std::endl;
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 3)
    return 1;

  const std::string rsa_path(argv[1]);
  const std::string rsa_pub_path(argv[2]);
  return RunCmds(rsa_path, rsa_pub_path);
}
