// Uses an encrypted key to crypt and decrypt a message.
//
// Usage: ./pbe_encrypt /path/pbe_crypter_key_set
//
#include <iostream>
#include <string>

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

using namespace keyczar;
using namespace keyczar::base;

int PBEEncryptAndDecrypt(const std::string& location) {
  ScopedSafeString password(new std::string("cartman"));

  // Instanciates a new reader object.
  scoped_ptr<rw::KeysetReader> reader(
      new rw::KeysetPBEJSONFileReader(location, *password));

  // Reads keys from key set.
  scoped_ptr<Keyczar> crypter(Crypter::Read(*reader));
  if (crypter.get() == NULL)
    return 1;

  const std::string input("Secret message");
  std::string ciphertext;
  // Encrypts input data.
  if (!crypter->Encrypt(input, &ciphertext)) {
    std::cerr << "Failed to encrypt input data." << std::endl;
    return 1;
  }

  std::cout << "Plaintext: " << input << std::endl;
  std::cout << "Ciphertext (base64w): " << ciphertext << std::endl;

  std::string decrypted_input;
  // Decrypts ciphertext.
  if (!crypter->Decrypt(ciphertext, &decrypted_input)) {
    std::cerr << "Failed to decrypt ciphertext." << std::endl;
    return 1;
  }

  if (input != decrypted_input) {
    std::cerr << "Decrypted data is not equal to input data." << std::endl;
    return 1;
  }

  std::cout << "Successfully encrypted and decrypted data!" << std::endl;
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2)
    return 1;

  const std::string location(argv[1]);
  return PBEEncryptAndDecrypt(location);
}
