# Signs a message and verifies its signature back. Uses raw encoding
# and base64w encoding.
#
# Example: python basic_sign.py ~/my-dsa
#
import os
import sys

import keyczar

def Sign(keyset_path):
    if not os.path.exists(keyset_path):
        return

    input = 'Message to sign'
    signer = keyczar.Signer.Read(keyset_path)
    signature = signer.Sign(input)

    print 'Message:', input
    print 'Signature:', signature

    verifier = keyczar.Verifier.Read(keyset_path)
    assert verifier.Verify(input, signature)

if __name__ == '__main__':
    if (len(sys.argv) != 2 or not os.path.exists(sys.argv[1])):
        print >> sys.stderr, "Provide a valid key set path as argument."
        sys.exit(1)
    Sign(sys.argv[1])
