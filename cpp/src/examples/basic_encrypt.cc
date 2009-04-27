#include <iostream>
#include <string>

#include <keyczar/keyczar.h>
#include <keyczar/keyset_encrypted_file_reader.h>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "An absolute key set location must be provided as argument"
              << std::endl;
    return 1;  // error
  }

  // The first argument must represent the keyset's location
  const std::string location(argv[1]);

  keyczar::Keyczar* encrypter = keyczar::Encrypter::Read(location);
  if (!encrypter)
    return 1;

  std::string input = "Secret message";
  std::string ciphertext;
  std::cout << "Encrypting: " << input << std::endl;
  bool result = encrypter->Encrypt(input, &ciphertext);
  delete encrypter;
  std::cout << "Ciphertext: " << ciphertext << std::endl;

  if (!result)
    return 1;
  return 0;
}
