# Encrypts and decrypts a short message from a PBE encrypted JSON key set.
#
# Example: python pbe_keyset.py ~/my-pbe-json-aes-encrypted password
#
import os
import sys

import keyczar

def Encrypt(crypted_path, password):
    if not os.path.exists(crypted_path):
        return

    input = 'Secret message'

    reader = keyczar.KeysetPBEJSONFileReader(crypted_path, password)
    crypter = keyczar.Crypter.Read(reader)
    ciphertext = crypter.Encrypt(input)

    print 'plaintext:', input
    print 'ciphertext:', ciphertext

    decrypted = crypter.Decrypt(ciphertext)
    assert decrypted == input

if __name__ == '__main__':
    if (len(sys.argv) != 3):
        print >> sys.stderr, "Provide a valid JSON key set path and a password as arguments."
        sys.exit(1)
    Encrypt(sys.argv[1], sys.argv[2])
