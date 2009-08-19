// Signs a message and verifies its signature back. Uses raw encoding
// and base64w encoding.
//
// Example: ./basic_sign ~/my-dsa
//
#include <cassert>
#include <iostream>
#include <string>

#include <keyczar/keyczar.h>

void SignAndVerify(const std::string& location) {
  keyczar::Keyczar* signer = keyczar::Signer::Read(location);
  if (!signer)
    return;

  std::string input = "My message to sign";
  std::string signature;
  std::cout << "Message: " << input << std::endl;

  bool result = signer->Sign(input, &signature);
  if (result) {
    std::cout << "Signature (Base64w): " << signature << std::endl;
    bool result = signer->Verify(input, signature);
    assert(result);
  }
  delete signer;
}

void SignAndVerifyBytes(const std::string& location) {
  keyczar::Keyczar* signer = keyczar::Signer::Read(location);
  if (!signer)
    return;

  signer->set_encoding(keyczar::Keyczar::NO_ENCODING);
  assert(signer->encoding() == keyczar::Keyczar::NO_ENCODING);

  std::string input = "My message to sign";
  std::string signature;
  bool result = signer->Sign(input, &signature);
  if (result) {
    bool result = signer->Verify(input, signature);
    assert(result);
  }
  delete signer;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "An absolute key set location must be provided as argument"
              << std::endl;
    return 1;  // error
  }

  // The first argument must represent the keyset's location
  const std::string location(argv[1]);

  SignAndVerify(location);
  SignAndVerifyBytes(location);

  return 0;
}
