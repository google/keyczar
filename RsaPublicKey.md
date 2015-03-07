# RSA Public Keys #

RSA Public keys are stored in JSON format and contain the following fields:
  * "modulus" : The RSA modulus (n) of this public key
  * "publicExponent": The RSA public exponent (e) of this public key
  * "size" : The size of the modulus in bits
  * _"padding"_: The type of padding to be used. Defaults to OAEP. This Field is not implemented in Python and C++._Optional_

Note: All fields are WebSafeBase64 encoded twos-complement representations of positive integers.

Possible digest sizes depend on key size and implementation. SHA1 is used by default

### Key Hash ###
The KeyHash components are: ` [leftTrimZero(modulus).length] + [leftTrimZero(modulus)] + [leftTrimZero(public_exponent).length] + [leftTrimZero(public_exponent)] `

If padding is PKCS don't left trim zero bytes.

### Meta ###
```
{
    ...
    "purpose": ("VERIFY"|"ENCRYPT"), 
    "type": "RSA_PUB", 
    ...
}
```

### JSON Representation ###
```
{
    "modulus": (modulus_bytes), 
    "publicExponent": (exp_bytes), 
    "size": (1024|2048|4096),
    "padding": ("OEAP"|"PKCS")
}
```
### Supported Sizes and Key types ###
#### Java ####
4096, 2048, 1024 bit key sizes supported
Defaults to 4096 bit key size

SHA1 is used for digests.
#### Python ####
2048, 4096, 1024, 768, 512 bit key sizes supported
Defaults to 2048 bit key size.

Digest size of 256 bytes
SHA1 is used for digests
#### C++ ####
512, 768, 1024, 2048, 3072, 4096 key sizes supported
Defaults to 2048 bit key size

If the compat flag is not set, then SHA224 is used as a digest for 2048 bit key sizes, SHA256 is used for 3072 bit key sizes, and SHA512 is used for 4096 bit keys.