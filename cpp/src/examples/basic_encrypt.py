# Encrypts and decrypts a short message.
#
# Example: python basic_encrypt.py ~/my-aes
#
import os
import sys

import keyczar

def Encrypt(keyset_path):
    if not os.path.isdir(keyset_path):
        return

    input = 'Secret message'
    encrypter = keyczar.Encrypter.Read(keyset_path)
    ciphertext = encrypter.Encrypt(input)

    print 'plaintext:', input
    print 'ciphertext:', ciphertext

    crypter = keyczar.Crypter.Read(keyset_path)
    decrypted = crypter.Decrypt(ciphertext)
    assert decrypted == input

if __name__ == '__main__':
    if (len(sys.argv) != 2):
        print >> sys.stderr, "Provide a key set path as argument."
        sys.exit(1)
    Encrypt(sys.argv[1])
