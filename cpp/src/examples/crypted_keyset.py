# Encrypts and decrypts a short message from an encrypted JSON key set.
#
# Example: python crypted_keyset.py ~/my-aes-encrypted ~/my-aes
#
import os
import sys

import keyczar

def Encrypt(crypted_path, crypter_path):
    if not os.path.exists(crypted_path) or not os.path.exists(crypter_path):
        return

    input = 'Secret message'

    key_crypter = keyczar.Crypter.Read(crypter_path)
    reader = keyczar.KeysetEncryptedJSONFileReader(crypted_path, key_crypter)

    crypter = keyczar.Crypter.Read(reader)
    ciphertext = crypter.Encrypt(input)

    print 'plaintext:', input
    print 'ciphertext:', ciphertext

    decrypted = crypter.Decrypt(ciphertext)
    assert decrypted == input

if __name__ == '__main__':
    if (len(sys.argv) != 3):
        print >> sys.stderr, "Provide two valids key sets paths as arguments:"
        print >> sys.stderr, sys.argv[0], "encrypted_json_keyset_path crypter_keyset_path"
        sys.exit(1)
    Encrypt(sys.argv[1], sys.argv[2])
