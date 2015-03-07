

# Keyczar C++ Tutorial #

## Install Keyczar C++ ##

Read the [README](http://keyczar.googlecode.com/git/cpp/README) file and follow the procedure to install Keyczar C++.


## Encrypting a plaintext with AES ##

  1. Create a new AES key set and add a new primary key
```
$ mkdir -p /tmp/aes
$ keyczart create --location=/tmp/aes --purpose=crypt
$ keyczart addkey --location=/tmp/aes --status=primary
```
  1. Save the following code in a file named basic\_encrypt.cc:
```
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
    std::cout << "Ciphertext (Base64w): " << ciphertext << std::endl;
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
  return 0;
}
```
  1. Compile this file with the following command:
```
g++ -lkeyczar -lcrypto -o basic_encrypt -Wall -O2 basic_encrypt.cc
```
  1. Finally execute basic\_encrypt:
```
$ ./basic_encrypt /tmp/aes 
Plaintext: Secret message
Ciphertext (Base64w): AMGIZvbQneGAnWCkfYxOdLuefKdqtQS1-tlffEdkxTcvOCCrGcl9kU_6pFQwyEzDFs5xR9w7hadS
```

Note: the same code could also work with RSA key sets (created for encrypting and decrypting purpose). But in this case remember that the size of the plaintext must be less than ` key_size (in bytes) - 41 `.

## Signing a message with ECDSA ##

_Added with [revision 396](http://code.google.com/p/keyczar/source/detail?r=396)_

  1. Create a new ECDSA key set and add a new primary key
```
$ mkdir -p /tmp/ecdsa
$ keyczart create --purpose=sign --location=/tmp/ecdsa --asymmetric=ecdsa
$ keyczart addkey --location=/tmp/ecdsa --status=primary 
```
  1. Save the following code in a file named basic\_sign.cc:
```
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

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "An absolute key set location must be provided as argument"
              << std::endl;
    return 1;  // error
  }

  // The first argument must represent the keyset's location
  const std::string location(argv[1]);

  SignAndVerify(location);
  return 0;
}
```
  1. Compile this file with the command:
```
g++ -lkeyczar -lcrypto -o basic_sign -Wall -O2 basic_sign.cc
```
  1. Finally execute basic\_sign:
```
$ ./basic_sign /tmp/ecdsa 
Message: My message to sign
Signature (Base64w): ADgjArEwPAIcT-tUlkVVuiRnKIDGPFslK4h2ki_SVet9rqCg4gIcRotyp4QkcFls6Vqw7MHEH0cpF4XGZlBeFpu2DA
```

Note: the same code could also work with RSA (created for signing purpose), DSA or HMAC key sets.

## Using PBE (password-based encryption) to encrypt keys ##

_Added with [revision 438](http://code.google.com/p/keyczar/source/detail?r=438)_

It is possible to protect keys inserted in a key set with a password. Its is not a requirement but it is more convenient to assign the same password for each keys in a same key set, otherwise it won't be possible to read this key set through the command line tool ` keyczart ` and you would have to implement your own code (but it is technically possible) for reading this key set.

  * Create a new encrypted key set using a PBE algorithm as crypter
```
$ keyczart create --location=/tmp/pbe_json --purpose=crypt --name="TestPBE"
$ keyczart addkey --location=/tmp/pbe_json --status=active --pass=cartman
$ keyczart addkey --location=/tmp/pbe_json --status=primary --pass=       
[Keyczar] For each key of this key set enter its password
Enter PBE password: <<type 'cartman'>>
[Keyczar] Adding new key...
Enter PBE password: <<type 'cartman'>>
```

` cartman ` is used as password, when the second key is created the password is not provided with the command so it will be prompted interactively. Type ` cartman ` a first time to read the previously added key and type it a second time to set the password for the new key.

Keys are AES encrypted using HMAC-SHA1 or HMAC-SHA256 (when available) as pseudo random function to derive the AES key from the initial password for more details read [PKCS5 standard](http://www.rsa.com/rsalabs/node.asp?id=2127) and OpenSSL's implementation.

  * A key from this key set looks like: ` key ` is a serialized JSON key string encrypted and represented as a web-safe base64 string.
```
$ cat /tmp/pbe_json/2
{
   "cipher": "AES128",
   "hmac": "HMAC_SHA1",
   "iterationCount": 4096,
   "iv": "RUpDvOWjHB2gtAvXDdo5Gg",
   "key": "SdEft4dhLg2jruTOndtTREsC00g5XKbcatBExkk296kSNinN-BbspOCHGfA9j3LWaSxEtme5y4e0tr9te6lXFgqLMTmT7kmZWAJ5bg",
   "salt": "3Ie7jxIsGNKbYjkwpvM7qA"
}
```

  * You can then use this key set from your code with corresponding ` KeysetPBEJSONFileReader ` reader and use it to perform any common actions such as encrypting data:
```
#include <iostream>
#include <string>

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

using namespace keyczar;
using namespace keyczar::base;

int PBEEncryptAndDecrypt() {
  // Obviously do not use /tmp to store your reals keys...
  const std::string location("/tmp/pbe_json");
  ScopedSafeString password(new std::string("cartman"));
  const std::string input("Secret message");

  // Instanciates a new reader object.
  scoped_ptr<rw::KeysetReader> reader(
      new rw::KeysetPBEJSONFileReader(location, *password));

  // Reads keys from key set.
  scoped_ptr<Keyczar> crypter(Crypter::Read(*reader));
  if (crypter.get() == NULL)
    return 1;

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

int main() {
  return PBEEncryptAndDecrypt();
}
```

  * Save this code into ` pbe_encrypt.cc ` and compile it with the following command:
```
$ g++ -W -Wall -O2 pbe_encrypt.cc -o pbe_encrypt -lkeyczar -lcrypto
```

  * Finally execute it:
```
$ ./pbe_encrypt                                                    
Plaintext: Secret message
Ciphertext (base64w): AFNxHWu3ntcdwcawY3vxkliFXrWdfKr0fMyYw_ZKB89zLqqT-rBjBYvGfsgXpegwHne9oWP2n96Y
Successfully encrypted and decrypted data!
```

## Using raw bytes instead of Base64 encoding ##

_Added with [revision 396](http://code.google.com/p/keyczar/source/detail?r=396)_

By default when you call ` Encrypt() ` the string result is Base64 web-safe encoded which increase by 37% the size of the ciphertext compared to its binary representation, so if you don't need this encoding you can use the following code:

```
  [...]
  // Snippet extracted from src/examples/basic_encrypt.cc
  keyczar::Keyczar* crypter = keyczar::Crypter::Read(location);
  if (!crypter)
    return;

  crypter->set_encoding(keyczar::Keyczar::NO_ENCODING);

  std::string input = "Secret message";
  std::string ciphertext;
  bool result = crypter->Encrypt(input, &ciphertext);
  [...] 
```

## Compressing input plaintext before encryption ##

_Added with [revision 433](http://code.google.com/p/keyczar/source/detail?r=433)_

By default plaintexts are encrypted without any compression. However in some cases you might want compress your plaintext before encrypting it. This example shows how to transparently apply the Zlib compression algorithm to your data (currently only algorithms GZip and Zlib are supported).

```
  [...]
  keyczar::Keyczar* crypter = keyczar::Crypter::Read(location);
  if (!crypter)
    return;

  crypter->set_compression(keyczar::Keyczar::ZLIB);

  std::string input = "Secret message";
  std::string ciphertext;
  bool result = crypter->Encrypt(input, &ciphertext);
  [...]
```

## Managing keys directly from programs ##

_Modified with [revision 448](http://code.google.com/p/keyczar/source/detail?r=448)_

` keyczart ` is a very convenient tool to let you create and manage a set of keys from command line. However one program might also need to directly manipulate and manage keys itself. The class [KeyczarTool](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczar_tool.h) offers the same commands than ` keyczart ` through dedicated methods. The following example [keyczar\_tool.cc](http://keyczar.googlecode.com/git/cpp/src/examples/keyczar_tool.cc) shows how to create a key set and add new keys.

The constructor argument tells ` KeyczarTool ` to internally use a JSON reader and JSON writer to read and write target key set. This way, it is trivial to switch between readers and writers.
```
  scoped_ptr<KeyczarTool> kz_tool(new KeyczarTool(KeyczarTool::JSON_FILE));
  if (kz_tool.get() == NULL)
    return 1;
```

` CmdCreate ` creates a new empty key set. Its arguments specify that it will contain RSA keys and these keys will be used for signing data.
```
  if (!kz_tool->CmdCreate(
          rsa_path,
          KeyPurpose::SIGN_AND_VERIFY,  // key set purpose
          "MyRSASigner",                // key set name
          KeyczarTool::RSA)) {          // asymmetric cipher type
    std::cerr << "Command 'create' failed." << std::endl;
    return 1;
  }
```

` CmdAddKey ` is called two times to add new keys to ` rsa_path `. Each call adds a new password encrypted ` active ` key. ` pbe_encryption ` and ` password ` are used for writing encrypted these new keys. Each return value must be strictly positive and provide the version number assigned with this new key. This version number is needed by key management methods (` CmdPromote `, ` CmdDemote ` and ` CmdRevoke `). Also note that the first inserted key sets the ` encrypted ` flag of the key set (for its lifetime), all successive calls are expected to be coherent with this choice.
```
  const KeyczarTool::KeyEncryption pbe_encryption = KeyczarTool::PBE;
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

  if (kz_tool->CmdAddKey(rsa_path, KeyStatus::ACTIVE, 0, pbe_encryption,
                         *password) <= 0) {
    std::cerr << "Command 'addkey' failed." << std::endl;
    return 1;
  }
```

` CmdPromote ` promotes ` key1_version `. Its status was ` active ` therefore its new status after this call will be promoted to ` primary `.
```
  if (!kz_tool->CmdPromote(rsa_path, key1_version)) {
    std::cerr << "Command 'promote' failed." << std::endl;
    return 1;
  }
```

` CmdPubKey ` exports public keys to a new key set located inside ` rsa_pub_path ` directory. All actives and primary keys from ` rsa_path ` are iterated and contribute a public key. As before ` pbe_encryption ` and ` password ` are required to read encrypted ` rsa_path ` keys.
```
  if (!kz_tool->CmdPubKey(rsa_path, rsa_pub_path, pbe_encryption, *password)) {
    std::cerr << "Command 'pubkey' failed." << std::endl;
    return 1;
  }
```

## Importing PEM Private keys ##

_Added with [revision 396](http://code.google.com/p/keyczar/source/detail?r=396)_

It it possible to import [PEM](http://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions) private keys to your key set with the command 'importkey'. It supports RSA, DSA and EC keys. Here is an example:

  1. Generate a new EC key from OpenSSL:
```
$ openssl ecparam -out ec_param.pem -name prime256v1
$ openssl ecparam -in ec_param.pem -genkey | openssl ec -aes256 -out ec_priv_encrypted.pem 
```
  1. Add this key to your key set:
```
$ keyczart importkey --location=/tmp/ecdsa --key=/<absolute_path>/ec_priv_encrypted.pem
$ cat /tmp/ecdsa/2
{
   "namedCurve": "prime256v1",
   "privateKey": "fII5zGf6GkdbXVqakuy05kWoTj0-xdTjK7HaihJev10",
   "publicKey": {
      "namedCurve": "prime256v1",
      "publicBytes": "BI5pewY2Fwmds5Frs1ZcwLN_ZVLmRj_t_81e5wsb62A-
VAgUHn9SS0COW5uWJaakkeNsnWJ0RdFzfcUZyCHZKmA"
   }
} 
```
Obviously if the target key set is encrypted it is possible to append ` --crypter ` or ` --pass ` argument to the previous command to provide a crypter location or a password.


## Exporting private keys ##

_Added with [revision 438](http://code.google.com/p/keyczar/source/detail?r=438)_

Use command ` exportkey ` to easily export primary private keys using [PKCS8](http://www.rsa.com/rsalabs/node.asp?id=2130) representation format. Exported keys are AES encrypted using PKCS5 PBE algorithm. Obviously exported keys can be imported via command ` importkey ` to differents set of keys.

  * Create a new key set and export its primary key:
```
$ keyczart create --location=/tmp/ecdsa --purpose=sign --asymmetric=ecdsa
$ keyczart addkey --location=/tmp/ecdsa --status=primary 
$ keyczart exportkey --location=/tmp/ecdsa --dest=/tmp/ecdsa/ecdsa_priv.pem 
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

  * Visualize its fields with OpenSSL:
```
$ openssl ec -in /tmp/ecdsa/ecdsa_priv.pem -passin pass:cartman -text
read EC key
Private-Key: (224 bit)
priv:
    51:ca:df:93:3e:05:ec:50:fa:36:60:27:63:6e:32:
    a1:31:3b:c7:f1:52:4b:ba:56:70:a1:1f:9b
pub: 
    04:ba:eb:a4:f4:f3:02:11:38:73:09:2a:98:c1:d9:
    16:c8:df:87:c8:07:95:a0:4e:26:af:a8:d7:9c:c2:
    2f:c5:b2:19:6e:9b:3a:a6:29:87:fc:5d:f5:0a:ae:
    97:7b:40:26:92:31:5d:1c:28:f0:7d:bc
ASN1 OID: secp224r1
writing EC key
-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHFHK35M+BexQ+jZgJ2NuMqExO8fxUku6VnChH5ugBwYFK4EEACGhPAM6
AAS666T08wIROHMJKpjB2RbI34fIB5WgTiavqNecwi/FshlumzqmKYf8XfUKrpd7
QCaSMV0cKPB9vA==
-----END EC PRIVATE KEY-----
```

## Additional examples ##

The previous examples as well as additionals examples are availables under [src/examples](http://keyczar.googlecode.com/git/cpp/src/#src/examples). Likewise here are the headers of the two main interfaces [keyczar.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar.h) and [keyczar\_tool.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczar_tool.h).