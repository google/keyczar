#include "base/at_exit.h"
#include "base/command_line.h"
#include "testing/gtest/include/gtest/gtest.h"

#include "keyczar/crypto_factory.h"

int main(int argc, char** argv) {
  // Make sure that we setup an AtExitManager so Singleton objects will be
  // destroyed. Singleton are used in the unittests by the code behind
  // PathService. Do not use PathService in the keyczar library.
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);
  testing::InitGoogleTest(&argc, argv);

  // Before any cryptographic operation initializes the random engine
  // (seeding...). However this step is useless under Linux with OpenSSL.
  keyczar::CryptoFactory::Rand();

  int result = RUN_ALL_TESTS();
  return result;
}
