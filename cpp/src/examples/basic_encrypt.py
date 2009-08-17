# Encrypts and decrypts a short message. Uses raw encoding, base64w
# encoding and zlib compression.
#
# Example: python basic_encrypt.py ~/my-aes
#
import os
import sys

import keyczar

def EncryptAndDecrypt(keyset_path):
    input = 'Secret message'
    encrypter = keyczar.Encrypter.Read(keyset_path)
    ciphertext_b64 = encrypter.Encrypt(input)

    print 'plaintext:', input
    print 'ciphertext (base64w):', ciphertext_b64

    crypter = keyczar.Crypter.Read(keyset_path)
    assert crypter.Decrypt(ciphertext_b64) == input

def EncryptAndDecryptBytes(keyset_path):
    input = 'Secret message'
    crypter = keyczar.Crypter.Read(keyset_path)
    crypter.set_encoding(crypter.NO_ENCODING)
    ciphertext_bytes = crypter.Encrypt(input)
    assert crypter.Decrypt(ciphertext_bytes) == input

def EncryptAndDecryptCompressed(keyset_path):
    input = 'Secret message'
    crypter = keyczar.Crypter.Read(keyset_path)
    crypter.set_compression(crypter.ZLIB)
    ciphertext_bytes = crypter.Encrypt(input)
    assert crypter.Decrypt(ciphertext_bytes) == input

if __name__ == '__main__':
    if (len(sys.argv) != 2 or not os.path.exists(sys.argv[1])):
        print >> sys.stderr, "Provide a key set path as argument."
        sys.exit(1)
    EncryptAndDecrypt(sys.argv[1])
    EncryptAndDecryptBytes(sys.argv[1])
    EncryptAndDecryptCompressed(sys.argv[1])
