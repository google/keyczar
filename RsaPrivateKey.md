# RSA Private Keys #

RSA Private keys contain the following fields:
  * "publicKey": A JSON representation of this private key's corresponding RsaPublicKey.
  * "privateExponent": The RSA private exponent (d) of this private key
  * "primeP": A secret prime factor (p) of the RSA modulus
  * "primeQ": A secret prime factor (q) of the RSA modulus
  * "primeCoefficientP": The private exponent d modulo prime p-1
  * "primeCoefficientQ": The private exponent d modulo prime q-1
  * "crtCoefficient": The inverse of the prime q modulo the prime p
  * "size" : The size of the modulus in bits

Note: All fields are WebSafeBase64 encoded twos-complement representations of positive integers.

Possible digest sizes are 128, 256, 512 or 256 depending on key size and implementation. SHA1 is used for digests

### Key Hash ###
The KeyHash components are: ` [leftTrimZero(modulus).length] + [leftTrimZero(modulus)] + [leftTrimZero(public_exponent).length] + [leftTrimZero(public_exponent)] `

If padding is PKCS don't left trim zero bytes.

### Meta ###
```
{
    ...
    "purpose": ("SIGN_AND_VERIFY"|"DECRYPT_AND_ENCRYPT"), 
    "type": "RSA_PRIV", 
    ...
}
```

### JSON Representation ###
```
{
    "crtCoefficient": (crt_bytes), 
    "primeExponentP": (exp_p_bytes), 
    "primeExponentQ": (exp_q_bytes), 
    "primeP": (p_bytes), 
    "primeQ": (q_bytes), 
    "privateExponent": (exp_bytes)
    "publicKey": {
        "modulus": (modulus_bytes), 
        "publicExponent": (exp_bytes), 
        "size": (1024|2048|4096),
        "padding": ("OEAP"|"PKCS")
    }, 
    "size": (1024|2048|4096)
}
```
### Supported Sizes and Key types ###
#### Java ####
4096, 2048, 1024 bit key sizes supported
Defaults to 4096 bit key size
#### Python ####
2048, 4096, 1024, 768, 512 bit key sizes supported
Defaults to 2048 bit key size
#### C++ ####
512, 768, 1024, 2048, 3072, 4096 key sizes supported
Defaults to 2048 bit key size