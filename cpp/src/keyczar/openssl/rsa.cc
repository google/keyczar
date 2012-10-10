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
#include <keyczar/openssl/rsa.h>

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <string.h>

#include <keyczar/base/file_util.h>
#include <keyczar/base/logging.h>
#include <keyczar/base/stl_util-inl.h>

namespace {

int DigestAlgorithmToNid(
    const keyczar::MessageDigestImpl::DigestAlgorithm digest_algorithm) {
  switch (digest_algorithm) {
    case keyczar::MessageDigestImpl::SHA1:
      return NID_sha1;
    case keyczar::MessageDigestImpl::SHA224:
      return NID_sha224;
    case keyczar::MessageDigestImpl::SHA256:
      return NID_sha256;
    case keyczar::MessageDigestImpl::SHA384:
      return NID_sha384;
    case keyczar::MessageDigestImpl::SHA512:
      return NID_sha512;
    default:
      NOTREACHED();
  }
  return 0;
}

}  // namespace

namespace keyczar {

namespace openssl {

RSAOpenSSL::RSAOpenSSL(RSA* key, bool private_key, RsaPadding padding)
    : key_(key), private_key_(private_key) {
  set_padding(padding);
}

static BIGNUM* ConvertByteStringToBignum(const std::string& byte_string) {
  return BN_bin2bn(
      reinterpret_cast<unsigned char*>(const_cast<char*>(byte_string.data())),
      byte_string.length(),
      NULL);
}

static bool ConvertBignumToByteString(const BIGNUM* bignum, std::string* byte_string) {
  if (!bignum)
    return false;

  int bignum_length = BN_num_bytes(bignum);
  unsigned char byte_array[bignum_length + 1];

  if (BN_bn2bin(bignum, byte_array + 1) != bignum_length) {
    PrintOSSLErrors();
    return false;
  }

  // Set the MSB to 0 if the high order bit is set, to be compatible with the
  // Java implementation.  The Java implementation uses BigInteger.toByteArray
  // to produce the byte string representation, but because Java's BigIntegers
  // are signed, it will prepend a zero byte if otherwise the high order bit
  // would be set (which would make the number negative in 2s complement).
  if (byte_array[1] & 0x80) {
    byte_array[0] = 0;
    byte_string->assign(reinterpret_cast<char*>(byte_array),
			sizeof(byte_array));
  } else {
    byte_string->assign(reinterpret_cast<char*>(byte_array + 1),
			sizeof(byte_array) - 1);
  }

  memset(byte_array, 0, sizeof(byte_array));
  return true;
}

// static
RSAOpenSSL* RSAOpenSSL::Create(const RSAIntermediateKey& key,
                               bool private_key) {
  ScopedRSAKey rsa_key(RSA_new());
  if (rsa_key.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  rsa_key->n = ConvertByteStringToBignum(key.n);
  rsa_key->e = ConvertByteStringToBignum(key.e);

  if (!rsa_key->n || !rsa_key->e)
    return NULL;

  if (!private_key)
    return new RSAOpenSSL(rsa_key.release(), private_key, key.padding);

  rsa_key->d = ConvertByteStringToBignum(key.d);
  rsa_key->p = ConvertByteStringToBignum(key.p);
  rsa_key->q = ConvertByteStringToBignum(key.q);
  rsa_key->dmp1 = ConvertByteStringToBignum(key.dmp1);
  rsa_key->dmq1 = ConvertByteStringToBignum(key.dmq1);
  rsa_key->iqmp = ConvertByteStringToBignum(key.iqmp);

  if (!rsa_key->d || !rsa_key->p || !rsa_key->q || !rsa_key->dmp1 ||
      !rsa_key->dmq1 || !rsa_key->iqmp)
    return NULL;

  // Checks it is a valid well-formed private key.
  if (!RSA_check_key(rsa_key.get()))
    return NULL;

  return new RSAOpenSSL(rsa_key.release(), private_key, key.padding);
}

// static
RSAOpenSSL* RSAOpenSSL::GenerateKey(int size, RsaPadding padding) {
  ScopedRSAKey rsa_key(RSA_new());
  ScopedBIGNUM public_exponent(BN_new());

  if (!rsa_key.get() ||
      !public_exponent.get() ||
      !BN_set_word(public_exponent.get(), RSA_F4) ||
      !RSA_generate_key_ex(rsa_key.get(), size, public_exponent.get(), NULL)) {
    PrintOSSLErrors();
    return NULL;
  }

  // Checks it is a valid well-formed private key.
  if (!RSA_check_key(rsa_key.get())) {
    LOG(ERROR) << "Invalid RSA key";
    return NULL;
  }

  return new RSAOpenSSL(rsa_key.release(),
                        true /* private_key */,
                        padding);
}

// static
RSAOpenSSL* RSAOpenSSL::CreateFromPEMPrivateKey(const std::string& filename,
                                                const std::string* passphrase,
                                                RsaPadding padding) {
  // Load the disk based private key.
  ScopedEVPPKey evp_pkey(ReadPEMPrivateKeyFromFile(filename, passphrase));
  if (evp_pkey.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  if (evp_pkey->pkey.rsa == NULL) {
    LOG(ERROR) << "Invalid RSA private key";
    return NULL;
  }

  // Duplicate the RSA key component.
  ScopedRSAKey rsa_key(EVP_PKEY_get1_RSA(evp_pkey.get()));
  if (rsa_key.get() == NULL) {
    PrintOSSLErrors();
    return NULL;
  }

  // Checks it is a valid well-formed key.
  if (!RSA_check_key(rsa_key.get())) {
    LOG(ERROR) << "Invalid RSA key";
    return NULL;
  }

  return new RSAOpenSSL(rsa_key.release(),
                        true /* private_key */,
                        padding);
}

bool RSAOpenSSL::ExportPrivateKey(const std::string& filename,
                                  const std::string* passphrase) const {
  ScopedEVPPKey evp_key(EVP_PKEY_new());
  if (key_.get() &&
      private_key_ &&
      evp_key.get() &&
      EVP_PKEY_set1_RSA(evp_key.get(), key_.get()))
    return WritePEMPrivateKeyToFile(evp_key.get(), filename, passphrase);
  else
    return false;
}

bool RSAOpenSSL::GetAttributes(RSAIntermediateKey* key) {
  return (key &&
          key_.get() &&
          private_key_ &&
          GetPublicAttributes(key) &&
          ConvertBignumToByteString(key_->d, &(key->d)) &&
          ConvertBignumToByteString(key_->p, &(key->p)) &&
          ConvertBignumToByteString(key_->q, &(key->q)) &&
          ConvertBignumToByteString(key_->dmp1, &(key->dmp1)) &&
          ConvertBignumToByteString(key_->dmq1, &(key->dmq1)) &&
          ConvertBignumToByteString(key_->iqmp, &(key->iqmp)));
}

bool RSAOpenSSL::GetPublicAttributes(RSAIntermediateKey* key) {
  if (key == NULL || key_.get() == NULL)
    return false;

  key->padding = padding();
  return (ConvertBignumToByteString(key_->n, &(key->n)) &&
          ConvertBignumToByteString(key_->e, &(key->e)));
}

RsaPadding RSAOpenSSL::padding() const {
  switch (padding_) {
    case RSA_PKCS1_PADDING:
      return PKCS;
    case RSA_PKCS1_OAEP_PADDING:
      return OAEP;
    default:
      LOG(FATAL) << "Invalid padding (indicates a code defect)";
      return UNDEFINED;
  }
}

void RSAOpenSSL::set_padding(RsaPadding padding) {
  switch (padding) {
    case OAEP:
      padding_ = RSA_PKCS1_OAEP_PADDING;
      break;
    case PKCS:
      padding_ = RSA_PKCS1_PADDING;
      break;
    case UNDEFINED:
      LOG(FATAL) << "Padding mode must be selected (code defect)";
      break;
    default:
      LOG(FATAL) << "Unknown padding mode (code defect)";
      break;
  }
}

bool RSAOpenSSL::Sign(const MessageDigestImpl::DigestAlgorithm digest_algorithm,
                      const std::string& message_digest,
                      std::string* signature) const {
  if (key_.get() == NULL || signature == NULL || !private_key_)
    return false;

  int nid = DigestAlgorithmToNid(digest_algorithm);
  if (nid == 0)
    return false;

  uint32 rsa_size = RSA_size(key_.get());
  base::STLStringResizeUninitialized(signature, rsa_size);

  uint32 signature_length = 0;
  if (RSA_sign(nid,
               reinterpret_cast<unsigned char*>(
                   const_cast<char*>(message_digest.data())),
               message_digest.length(),
               reinterpret_cast<unsigned char*>(
                   base::string_as_array(signature)),
               &signature_length,
               key_.get()) != 1) {
    PrintOSSLErrors();
    return false;
  }

  CHECK_LE(signature_length, rsa_size);
  signature->resize(signature_length);
  return true;
}

bool RSAOpenSSL::Verify(
    const MessageDigestImpl::DigestAlgorithm digest_algorithm,
    const std::string& message_digest,
    const std::string& signature) const {
  if (key_.get() == NULL)
    return false;

  int nid = DigestAlgorithmToNid(digest_algorithm);
  if (nid == 0)
    return false;

  if (RSA_verify(nid,
                 reinterpret_cast<unsigned char*>(
                     const_cast<char*>(message_digest.data())),
                 message_digest.length(),
                 reinterpret_cast<unsigned char*>(
                     const_cast<char*>(signature.data())),
                 signature.length(),
                 key_.get()) != 1) {
    PrintOSSLErrors();
    return false;
  }
  return true;
}

bool RSAOpenSSL::Encrypt(const std::string& data,
                         std::string* encrypted) const {
  if (key_.get() == NULL || encrypted == NULL)
    return false;

  uint32 rsa_size = RSA_size(key_.get());

  if (data.length() >= rsa_size - 41) {
    LOG(WARNING) <<
        "Too long length of input data must be inferior to key size - 41.";
    return false;
  }

  unsigned char encrypted_buffer[rsa_size];
  int encrypted_len = RSA_public_encrypt(data.length(),
                                         reinterpret_cast<unsigned char*>(
                                             const_cast<char*>(data.data())),
                                         encrypted_buffer,
                                         key_.get(),
                                         padding_);
  if (encrypted_len == -1) {
    PrintOSSLErrors();
    return false;
  }
  CHECK_EQ(encrypted_len, static_cast<int>(rsa_size));

  encrypted->assign(reinterpret_cast<char*>(encrypted_buffer), rsa_size);
  return true;
}

bool RSAOpenSSL::Decrypt(const std::string& encrypted,
                         std::string* data) const {
  if (key_.get() == NULL || data == NULL || !private_key_)
    return false;

  int rsa_size = RSA_size(key_.get());
  unsigned char data_buffer[rsa_size];

  int data_len = RSA_private_decrypt(encrypted.length(),
                                     reinterpret_cast<unsigned char*>(
                                         const_cast<char*>(encrypted.data())),
                                     data_buffer,
                                     key_.get(),
                                     padding_);
  if (data_len == -1) {
    PrintOSSLErrors();
    return false;
  }
  CHECK_LT(data_len, rsa_size - 41);

  data->assign(reinterpret_cast<char*>(data_buffer), data_len);
  return true;
}

int RSAOpenSSL::Size() const {
  if (key_.get() == NULL)
    return 0;

  return RSA_size(key_.get()) * 8;
}

bool RSAOpenSSL::Equals(const RSAOpenSSL& rhs) const {
  if (!key_.get() ||
      private_key() != rhs.private_key() ||
      BN_cmp(key_->n, rhs.key()->n) != 0 ||
      BN_cmp(key_->e, rhs.key()->e) != 0)
    return false;

  if (!private_key())
    return true;

  return (BN_cmp(key_->d, rhs.key()->d) == 0 &&
          BN_cmp(key_->p, rhs.key()->p) == 0 &&
          BN_cmp(key_->q, rhs.key()->q) == 0 &&
          BN_cmp(key_->dmp1, rhs.key()->dmp1) == 0 &&
          BN_cmp(key_->dmq1, rhs.key()->dmq1) == 0 &&
          BN_cmp(key_->iqmp, rhs.key()->iqmp) == 0);
}

}  // namespace openssl

}  // namespace keyczar
