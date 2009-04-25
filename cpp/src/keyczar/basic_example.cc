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
#include <iostream>
#include <string>

#include "keyczar/keyczar.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "An absolute key set location must be provided as argument"
              << std::endl;
    return 1;
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
