# Demonstrates KeyczarTool's basic commands and encrypts a short message.
#
# Example: python keyczar_tool.py ~/tmp-dir
#
import os
import sys

import keyczar

PLAINTEXT = 'Secret message'

def RunCommands(keyset_type, keyset_password, rsa_path, rsa_pub_path):
    kt = keyczar.KeyczarTool(keyset_type)
    # Creates a RSA key set for encryption
    kt.CmdCreate(rsa_path, keyczar.KeyPurpose.DECRYPT_AND_ENCRYPT,
                 "MyRSATest", keyczar.KeyczarTool.RSA)
    # Adds a first key
    kt.CmdAddKey(rsa_path, keyczar.KeyStatus.ACTIVE, 0,
                 keyczar.KeyczarTool.PBE, keyset_password)
    # Adds a second key
    version = kt.CmdAddKey(rsa_path, keyczar.KeyStatus.ACTIVE, 0,
                           keyczar.KeyczarTool.PBE, keyset_password)
    # Promotes this last key
    kt.CmdPromote(rsa_path, version)
    # Exports public keys
    kt.CmdPubKey(rsa_path, rsa_pub_path, keyczar.KeyczarTool.PBE,
                 keyset_password)

def EncryptMessage(rsa_pub_path):
    encrypter = keyczar.Encrypter.Read(rsa_pub_path)
    ciphertext = encrypter.Encrypt(PLAINTEXT)
    print 'Plaintext:', PLAINTEXT
    print 'Ciphertext (base64w):', ciphertext
    return ciphertext

def DecryptMessage(keyset_type, keyset_password, rsa_path, ciphertext):
    reader = keyczar.KeysetPBEJSONFileReader(rsa_path, keyset_password)
    crypter = keyczar.Crypter.Read(reader)
    plaintext = crypter.Decrypt(ciphertext)
    return plaintext

if __name__ == '__main__':
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        print >> sys.stderr, "Provide an empty temp directory as argument."
        sys.exit(1)

    rsa_path = os.path.join(sys.argv[1], 'rsa')
    rsa_pub_path = os.path.join(sys.argv[1], 'rsa_pub')
    if os.path.isdir(rsa_path) or os.path.isdir(rsa_pub_path):
        print >> sys.stderr, 'Error:', sys.argv[1], 'is not empty.'
        sys.exit(1)
    os.mkdir(rsa_path)
    os.mkdir(rsa_pub_path)

    keyset_type = keyczar.KeyczarTool.JSON_FILE
    keyset_password = 'cartman'

    RunCommands(keyset_type, keyset_password, rsa_path, rsa_pub_path)

    ciphertext = EncryptMessage(rsa_pub_path)
    plaintext = DecryptMessage(keyset_type, keyset_password, rsa_path,
                               ciphertext)

    assert PLAINTEXT == plaintext, 'mismatch plaintext / decrypted plaintext'

