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
#include <string>

#include <testing/gtest/include/gtest/gtest.h>

#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/path_service.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/keyczar.h>
#include <keyczar/keyczar_test.h>
#include <keyczar/keyset_encrypted_file_reader.h>
#include <keyczar/keyset_file_reader.h>
#include <keyczar/keyset_file_writer.h>

namespace keyczar {

TEST_F(KeyczarTest, AcceptablePurpose) {
  scoped_ptr<Signer> signer;
  scoped_ptr<UnversionedSigner> unversioned_signer;
  scoped_ptr<Verifier> verifier;
  scoped_ptr<UnversionedVerifier> unversioned_verifier;
  scoped_ptr<Encrypter> encrypter;
  scoped_ptr<Crypter> crypter;

  const FilePath rsa_priv_crypt_path = data_path_.Append("rsa");
  signer.reset(Signer::Read(rsa_priv_crypt_path.value()));
  ASSERT_FALSE(signer.get());
  unversioned_signer.reset(
      UnversionedSigner::Read(rsa_priv_crypt_path.value()));
  ASSERT_FALSE(unversioned_signer.get());
  crypter.reset(Crypter::Read(rsa_priv_crypt_path.value()));
  ASSERT_TRUE(crypter.get());
  encrypter.reset(Encrypter::Read(rsa_priv_crypt_path.value()));
  ASSERT_TRUE(encrypter.get());

  const FilePath rsa_priv_sign_path = data_path_.Append("rsa-sign");
  crypter.reset(Crypter::Read(rsa_priv_sign_path.value()));
  ASSERT_FALSE(crypter.get());
  signer.reset(Signer::Read(rsa_priv_sign_path.value()));
  ASSERT_TRUE(signer.get());
  unversioned_signer.reset(UnversionedSigner::Read(rsa_priv_sign_path.value()));
  ASSERT_TRUE(unversioned_signer.get());
  verifier.reset(Verifier::Read(rsa_priv_sign_path.value()));
  ASSERT_TRUE(verifier.get());

  const FilePath rsa_pub_sign_path = data_path_.Append("rsa-sign.public");
  encrypter.reset(Encrypter::Read(rsa_pub_sign_path.value()));
  ASSERT_FALSE(encrypter.get());
  signer.reset(Signer::Read(rsa_pub_sign_path.value()));
  ASSERT_FALSE(signer.get());
  verifier.reset(Verifier::Read(rsa_pub_sign_path.value()));
  ASSERT_TRUE(verifier.get());

  const FilePath aes_path = data_path_.Append("aes");
  signer.reset(Signer::Read(aes_path.value()));
  ASSERT_FALSE(signer.get());
  crypter.reset(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(crypter.get());
  encrypter.reset(Encrypter::Read(aes_path.value()));
  ASSERT_TRUE(encrypter.get());

  const FilePath hmac_path = data_path_.Append("hmac");
  crypter.reset(Crypter::Read(hmac_path.value()));
  ASSERT_FALSE(crypter.get());
  verifier.reset(Verifier::Read(hmac_path.value()));
  ASSERT_TRUE(verifier.get());
  signer.reset(Signer::Read(hmac_path.value()));
  ASSERT_TRUE(signer.get());
  unversioned_signer.reset(UnversionedSigner::Read(hmac_path.value()));
  ASSERT_TRUE(unversioned_signer.get());

  const FilePath dsa_priv_sign_path = data_path_.Append("dsa");
  crypter.reset(Crypter::Read(dsa_priv_sign_path.value()));
  ASSERT_FALSE(crypter.get());
  signer.reset(Signer::Read(dsa_priv_sign_path.value()));
  ASSERT_TRUE(signer.get());
  unversioned_signer.reset(UnversionedSigner::Read(dsa_priv_sign_path.value()));
  ASSERT_TRUE(unversioned_signer.get());
  verifier.reset(Verifier::Read(dsa_priv_sign_path.value()));
  ASSERT_TRUE(verifier.get());

  const FilePath dsa_pub_sign_path = data_path_.Append("dsa.public");
  encrypter.reset(Encrypter::Read(dsa_pub_sign_path.value()));
  ASSERT_FALSE(encrypter.get());
  signer.reset(Signer::Read(dsa_pub_sign_path.value()));
  ASSERT_FALSE(signer.get());
  verifier.reset(Verifier::Read(dsa_pub_sign_path.value()));
  ASSERT_TRUE(verifier.get());
}

TEST_F(KeyczarTest, RSAEncryptAndDecrypt) {
  std::string encrypted, decrypted;

  const FilePath private_path = data_path_.Append("rsa");
  scoped_ptr<Encrypter> encrypter(Encrypter::Read(private_path.value()));
  ASSERT_TRUE(encrypter.get());
  EXPECT_TRUE(encrypter->Encrypt(input_data_, &encrypted));

  scoped_ptr<Crypter> crypter(Crypter::Read(private_path.value()));
  ASSERT_TRUE(crypter.get());
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, RSASignAnVerify) {
  std::string signature;

  const FilePath private_path = data_path_.Append("rsa-sign");
  scoped_ptr<Signer> signer(Signer::Read(private_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  const FilePath public_path = data_path_.Append("rsa-sign.public");
  scoped_ptr<Verifier> verifier(Verifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

// It is expected that this function raise these errors:
//   error:0407006A:rsa routines:RSA_padding_check_PKCS1_type_1:block type
//   is not 01
//   error:04067072:rsa routines:RSA_EAY_PUBLIC_DECRYPT:padding check failed
//
// This is because the unversioned algorithm has to try all the keys of the
// keyset in order to find if one match the signature. In this case, these
// errors were raised by the first key of the keyset which was not the primary
// key.
TEST_F(KeyczarTest, RSASignAnVerifyUnversioned) {
  std::string signature;

  const FilePath private_path = data_path_.Append("rsa-sign");
  scoped_ptr<UnversionedSigner> signer(
      UnversionedSigner::Read(private_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  const FilePath public_path = data_path_.Append("rsa-sign.public");
  scoped_ptr<UnversionedVerifier> verifier(
      UnversionedVerifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, RSADecrypt) {
  std::string encrypted, decrypted;

  const FilePath private_path = data_path_.Append("rsa");
  EXPECT_TRUE(file_util::ReadFileToString(
                  private_path.Append("1.out"), &encrypted));

  scoped_ptr<Crypter> crypter(Crypter::Read(private_path.value()));
  ASSERT_TRUE(crypter.get());
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, RSAVerify) {
  std::string signature;

  const FilePath private_path = data_path_.Append("rsa-sign");
  EXPECT_TRUE(file_util::ReadFileToString(
                  private_path.Append("1.out"), &signature));

  const FilePath public_path = data_path_.Append("rsa-sign.public");
  scoped_ptr<Verifier> verifier(Verifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, HMACSignAndVerify) {
  std::string signature;

  const FilePath hmac_path = data_path_.Append("hmac");
  scoped_ptr<Signer> signer(Signer::Read(hmac_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  scoped_ptr<Verifier> verifier(Verifier::Read(hmac_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, HMACSignAndVerifyUnversioned) {
  std::string signature;

  const FilePath hmac_path = data_path_.Append("hmac");
  scoped_ptr<UnversionedSigner> signer(
      UnversionedSigner::Read(hmac_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  scoped_ptr<UnversionedVerifier> verifier(
      UnversionedVerifier::Read(hmac_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, HMACVerify) {
  std::string signature;
  const FilePath hmac_path = data_path_.Append("hmac");
  EXPECT_TRUE(file_util::ReadFileToString(
                  hmac_path.Append("1.out"), &signature));

  scoped_ptr<Verifier> verifier(Verifier::Read(hmac_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, AESEncryptAndDecrypt) {
  std::string encrypted, decrypted;

  const FilePath aes_path = data_path_.Append("aes");
  scoped_ptr<Encrypter> encrypter(Encrypter::Read(aes_path.value()));
  ASSERT_TRUE(encrypter.get());
  EXPECT_TRUE(encrypter->Encrypt(input_data_, &encrypted));

  scoped_ptr<Crypter> crypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(crypter.get());
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, AESEncryptAndDecryptNoEncoding) {
  std::string encrypted, decrypted;

  const FilePath aes_path = data_path_.Append("aes");
  scoped_ptr<Encrypter> encrypter(Encrypter::Read(aes_path.value()));
  ASSERT_TRUE(encrypter.get());

  EXPECT_EQ(encrypter->encoding(), Keyczar::BASE64W);
  encrypter->set_encoding(Keyczar::NO_ENCODING);
  EXPECT_EQ(encrypter->encoding(), Keyczar::NO_ENCODING);

  EXPECT_TRUE(encrypter->Encrypt(input_data_, &encrypted));

  scoped_ptr<Crypter> crypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(crypter.get());

  EXPECT_EQ(crypter->encoding(), Keyczar::BASE64W);
  crypter->set_encoding(Keyczar::NO_ENCODING);
  EXPECT_EQ(crypter->encoding(), Keyczar::NO_ENCODING);

  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, AESDecrypt1) {
  std::string encrypted, decrypted;

  const FilePath aes_path = data_path_.Append("aes");
  EXPECT_TRUE(file_util::ReadFileToString(
                  aes_path.Append("1.out"), &encrypted));

  scoped_ptr<Crypter> crypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(crypter.get());
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, AESDecrypt2) {
  std::string encrypted, decrypted;

  const FilePath aes_path = data_path_.Append("aes");
  EXPECT_TRUE(file_util::ReadFileToString(
                  aes_path.Append("2.out"), &encrypted));

  scoped_ptr<Crypter> crypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(crypter.get());
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, AESCryptedEncryptAndDecrypt) {
  const FilePath aes_path = data_path_.Append("aes");
  scoped_ptr<Crypter> decrypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(decrypter.get());

  const FilePath aes_crypted_path = data_path_.Append("aes-crypted");
  KeysetEncryptedJSONFileReader encrypted_reader(
      aes_crypted_path.value(), decrypter.release());
  scoped_ptr<Crypter> crypter(Crypter::Read(encrypted_reader));
  ASSERT_TRUE(crypter.get());

  std::string encrypted, decrypted;
  EXPECT_TRUE(crypter->Encrypt(input_data_, &encrypted));
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, AESCryptedDecrypt1) {
  std::string encrypted, decrypted;

  const FilePath aes_path = data_path_.Append("aes");
  scoped_ptr<Crypter> decrypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(decrypter.get());

  const FilePath aes_crypted_path = data_path_.Append("aes-crypted");
  KeysetEncryptedJSONFileReader encrypted_reader(aes_crypted_path.value(),
                                             decrypter.release());
  scoped_ptr<Crypter> crypter(Crypter::Read(encrypted_reader));
  ASSERT_TRUE(crypter.get());

  EXPECT_TRUE(file_util::ReadFileToString(
                  aes_crypted_path.Append("1.out"), &encrypted));
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, AESCryptedDecrypt2) {
  std::string encrypted, decrypted;

  const FilePath aes_path = data_path_.Append("aes");
  scoped_ptr<Crypter> decrypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(decrypter.get());

  const FilePath aes_crypted_path = data_path_.Append("aes-crypted");
  KeysetEncryptedJSONFileReader encrypted_reader(aes_crypted_path.value(),
                                             decrypter.release());
  scoped_ptr<Crypter> crypter(Crypter::Read(encrypted_reader));
  ASSERT_TRUE(crypter.get());

  EXPECT_TRUE(file_util::ReadFileToString(
                  aes_crypted_path.Append("2.out"), &encrypted));
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input_data_, decrypted);
}

TEST_F(KeyczarTest, DSASignAnVerify) {
  std::string signature;

  const FilePath private_path = data_path_.Append("dsa");
  scoped_ptr<Signer> signer(Signer::Read(private_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  const FilePath public_path = data_path_.Append("dsa.public");
  scoped_ptr<Verifier> verifier(Verifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, DSASignAnVerifyUnversioned) {
  std::string signature;

  const FilePath private_path = data_path_.Append("dsa");
  scoped_ptr<UnversionedSigner> signer(
      UnversionedSigner::Read(private_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  const FilePath public_path = data_path_.Append("dsa.public");
  scoped_ptr<UnversionedVerifier> verifier(
      UnversionedVerifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, DSAVerify) {
  std::string signature;

  const FilePath private_path = data_path_.Append("dsa");
  EXPECT_TRUE(file_util::ReadFileToString(
                  private_path.Append("1.out"), &signature));

  const FilePath public_path = data_path_.Append("dsa.public");
  scoped_ptr<Verifier> verifier(Verifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, ECDSASignAnVerify) {
  std::string signature;

  const FilePath private_path = data_path_.Append("ecdsa");
  scoped_ptr<Signer> signer(Signer::Read(private_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  const FilePath public_path = data_path_.Append("ecdsa.public");
  scoped_ptr<Verifier> verifier(Verifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, ECDSASignAnVerifyUnversioned) {
  std::string signature;

  const FilePath private_path = data_path_.Append("ecdsa");
  scoped_ptr<UnversionedSigner> signer(
      UnversionedSigner::Read(private_path.value()));
  ASSERT_TRUE(signer.get());
  EXPECT_TRUE(signer->Sign(input_data_, &signature));

  const FilePath public_path = data_path_.Append("ecdsa.public");
  scoped_ptr<UnversionedVerifier> verifier(
      UnversionedVerifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, ECDSAVerify) {
  std::string signature;

  const FilePath private_path = data_path_.Append("ecdsa");
  EXPECT_TRUE(file_util::ReadFileToString(
                  private_path.Append("1.out"), &signature));

  const FilePath public_path = data_path_.Append("ecdsa.public");
  scoped_ptr<Verifier> verifier(Verifier::Read(public_path.value()));
  ASSERT_TRUE(verifier.get());
  EXPECT_TRUE(verifier->Verify(input_data_, signature));
}

TEST_F(KeyczarTest, AESBigBufferEncryptAndDecrypt) {
  std::string encrypted, decrypted, input;

  const FilePath aes_path = data_path_.Append("aes");
  scoped_ptr<Crypter> crypter(Crypter::Read(aes_path.value()));
  ASSERT_TRUE(crypter.get());

  scoped_ptr_malloc<char> input_buffer;
  int num_bytes = 10000000;
  input_buffer.reset(reinterpret_cast<char*>(malloc(num_bytes * sizeof(char))));
  ASSERT_TRUE(input_buffer.get());

  input.assign(input_buffer.get(), num_bytes);
  input_buffer.reset();

  EXPECT_TRUE(crypter->Encrypt(input, &encrypted));
  EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
  EXPECT_EQ(input, decrypted);
}

TEST_F(KeyczarTest, Compression) {
  const FilePath private_path = data_path_.Append("rsa");
  scoped_ptr<Crypter> crypter(Crypter::Read(private_path.value()));
  ASSERT_TRUE(crypter.get());

  EXPECT_EQ(crypter->compression(), Keyczar::NO_COMPRESSION);

#if HAVE_ZLIB
  crypter->set_compression(Keyczar::GZIP);
  EXPECT_EQ(crypter->compression(), Keyczar::GZIP);

  {
    std::string encrypted, decrypted;
    EXPECT_TRUE(crypter->Encrypt(input_data_, &encrypted));
    EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
    EXPECT_EQ(input_data_, decrypted);
  }

  crypter->set_compression(Keyczar::ZLIB);
  EXPECT_EQ(crypter->compression(), Keyczar::ZLIB);

  {
    std::string encrypted, decrypted;
    EXPECT_TRUE(crypter->Encrypt(input_data_, &encrypted));
    EXPECT_TRUE(crypter->Decrypt(encrypted, &decrypted));
    EXPECT_EQ(input_data_, decrypted);
  }
#endif  // HAVE_ZLIB
}

}  // namespace keyczar
