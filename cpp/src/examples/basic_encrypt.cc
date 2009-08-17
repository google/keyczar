// Encrypts and decrypts a short message. Uses raw encoding, base64w
// encoding and zlib compression.
//
// Example: ./basic_encrypt ~/my-aes
//
#include <cassert>
#include <iostream>
#include <string>

#include <keyczar/keyczar.h>

void EncryptAndDecrypt(const std::string& location) {
  keyczar::Keyczar* crypter = keyczar::Crypter::Read(location);
  if (!crypter)
    return;

  std::string input = "Secret message";
  std::string ciphertext;
  std::cout << "Plaintext: " << input << std::endl;

  bool result = crypter->Encrypt(input, &ciphertext);
  if (result) {
    std::cout << "Ciphertext (base64w): " << ciphertext << std::endl;
    std::string decrypted_input;
    bool result = crypter->Decrypt(ciphertext, &decrypted_input);
    if (result)
      assert(input == decrypted_input);
  }
  delete crypter;
}

void EncryptAndDecryptBytes(const std::string& location) {
  keyczar::Keyczar* crypter = keyczar::Crypter::Read(location);
  if (!crypter)
    return;

  crypter->set_encoding(keyczar::Keyczar::NO_ENCODING);
  assert(crypter->encoding() == keyczar::Keyczar::NO_ENCODING);

  std::string input = "Secret message";
  std::string ciphertext;
  bool result = crypter->Encrypt(input, &ciphertext);
  if (result) {
    std::string decrypted_input;
    bool result = crypter->Decrypt(ciphertext, &decrypted_input);
    if (result)
      assert(input == decrypted_input);
  }
  delete crypter;
}

void EncryptAndDecryptCompressed(const std::string& location) {
  keyczar::Keyczar* crypter = keyczar::Crypter::Read(location);
  if (!crypter)
    return;

  crypter->set_compression(keyczar::Keyczar::ZLIB);
  assert(crypter->compression() == keyczar::Keyczar::ZLIB);

  std::string input = "Secret message";
  std::string ciphertext;
  bool result = crypter->Encrypt(input, &ciphertext);
  if (result) {
    std::string decrypted_input;
    bool result = crypter->Decrypt(ciphertext, &decrypted_input);
    if (result)
      assert(input == decrypted_input);
  }
  delete crypter;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "An absolute key set location must be provided as argument"
              << std::endl;
    return 1;  // error
  }

  // The first argument must represent the keyset's location
  const std::string location(argv[1]);

  EncryptAndDecrypt(location);
  EncryptAndDecryptBytes(location);
  EncryptAndDecryptCompressed(location);

  return 0;
}
