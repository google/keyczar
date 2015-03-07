# DSA Private Keys #

DSA private keys contain the following fields:
  * "publicKey": The JSON representation of the corresponding DsaPublicKey
  * "x": The secret exponent of this private key
  * "size" : The size of the modulus in bits

Note: All fields are WebSafeBase64 encoded twos-complement representations of positive integers.

The digest size is 384 bits. SHA1 is used for the digest.

### Key Hash ###
The KeyHash components are: ` [leftTrimZero(p).length] + [leftTrimZero(p)] + [leftTrimZero(q).length] + [leftTrimZero(q)] + [leftTrimZero(g).length] + [leftTrimZero(g)] + [leftTrimZero(y).length] + [leftTrimZero(y)] `

### Meta ###
The relevant parts of the [KeyMetadata](KeyMetadata.md) are as follows:
```
{
    ...
    "purpose": "SIGN_AND_VERIFY", 
    "type": "DSA_PUB",  
    ...
}
```

### JSON Representation ###
```
{
    "publicKey": {
        "g": (g_bytes), 
        "p": (p_bytes), 
        "q": (q_bytes), 
        "size": 1024, 
        "y": (y_bytes)
    }, 
    "size": 1024, 
    "x": (x_bytes)
}
```
### Supported Sizes and Key types ###
#### Java ####
1024 bit key size
#### Python ####
1024 bit key size
#### C++ ####
Defaults to 2048 bits
1024, 2048, 3072 bit key sizes supported

If the compat flag is not set, then SHA224 is used as a digest for 2048 bit key sizes and SHA256 is used for 3072 bit key sizes.