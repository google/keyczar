// Encrypts a file.
//
// Example: ./encrypt_file ~/my-aes src_filename dst_filename
//
#include <iostream>
#include <string>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cout << "An absolute key set location must be provided as argument"
              << std::endl;
    return 1;  // error
  }

  // The first argument must represent the keyset's location
  const std::string location(argv[1]);

  keyczar::Keyczar* encrypter = keyczar::Encrypter::Read(location);
  if (!encrypter)
    return 1;

  const FilePath input_file(argv[2]);
  std::string input;
  if (!keyczar::base::ReadFileToString(input_file, &input))
    return 1;

  std::string ciphertext;
  bool result = encrypter->Encrypt(input, &ciphertext);
  delete encrypter;
  if (!result)
    return 1;

  const FilePath output_file(argv[3]);
  if (!keyczar::base::WriteStringToFile(output_file, ciphertext))
    return 1;

  return 0;
}
