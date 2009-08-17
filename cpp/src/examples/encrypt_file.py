# Encrypts a file.
#
# Example: python encrypt_file.py ~/my-aes src_filename dst_filename
#
import os
import sys

import keyczar

def EncryptFile(keyset_path, in_file, out_file):
    if not os.path.exists(keyset_path):
        return

    encrypter = keyczar.Encrypter.Read(keyset_path)

    fo_in = file(in_file, 'r')
    fo_out = file(out_file, 'w')
    try:
        fo_out.write(encrypter.Encrypt(fo_in.read()))
    finally:
        fo_in.close
        fo_out.close

if __name__ == '__main__':
    if (len(sys.argv) != 4):
        print >> sys.stderr, "Usage:", sys.argv[0], "/key/path input_file output_file"
        sys.exit(1)
    EncryptDile(sys.argv[1], sys.argv[2], sys.argv[3])
