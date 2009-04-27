# Encrypts and decrypts a short message from an encrypted key set.
#
# Example: python basic_encrypt.py ~/my-aes-crypted ~/my-aes
#
import os
import sys

import keyczar

def Encrypt(crypted_path, crypter_path):
    if not os.path.isdir(crypted_path) or not os.path.isdir(crypter_path):
        return

    input = 'Secret message'

    key_crypter = keyczar.Crypter.Read(crypter_path)
    reader = keyczar.KeysetEncryptedFileReader(crypted_path, key_crypter)

    crypter = keyczar.Crypter.Read(reader)
    ciphertext = crypter.Encrypt(input)

    print 'plaintext:', input
    print 'ciphertext:', ciphertext

    decrypted = crypter.Decrypt(ciphertext)
    assert decrypted == input

if __name__ == '__main__':
    if (len(sys.argv) != 3):
        print >> sys.stderr, "Provide two key sets paths as argument:"
        print >> sys.stderr, sys.argv[0], "encrypted_keyset_path crypter_path"
        sys.exit(1)
    Encrypt(sys.argv[1], sys.argv[2])
