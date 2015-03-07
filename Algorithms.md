# Algorithms #

This page details the different cryptographic algorithms supported by Keyczar and some details about their support across different implementations.

Keys are stored as JSON strings with a meta JSON file and then seperate files for each key in that keyset. Numeric components (eg. int, long) use big-endian byte order. All byte strings are encoded using web-safe base64.


### Key Hash ###
Key hashes are used to distinguish keys in a keyset. It is assumed that no two keys will have the same hash within a keyset.

Key hashes are the first 4 bytes of a SHA1 digest of components that are dependent on algorithm.

### Key Data ###
Most fields in key data are implementation specific. "Size" is a common field among all implementation and declares the key size in bits.

### Meta ###
Each keyset is associated with one algorithm specified in the [KeyMetadata](KeyMetadata.md). The format of this metadata is shown below.
```
{
    "encrypted": (true|false), 
    "name": "Name of Keyset", 
    "purpose": ("ENCRYPT"|"ENCRYPT_AND_DECRYPT"|"VERIFY"|"SIGN_AND_VERIFY"), 
    "type": (algorithm_type), 
    "versions": [
        {
            "exportable": (true|false), 
            "status": ("PRIMARY"|"ACTIVE"|"INACTIVE"), 
            "versionNumber": (key_version_number)
        }, 
        ...
    ]
}
```


---

## HMAC using SHA1 ##
The digest size is 160 bits.

### Key Hash ###
The key hash components are: ` key_bytes `

### Meta ###
```
{
    ...
    "purpose": "SIGN_AND_VERIFY", 
    "type": "HMAC_SHA1", 
    ...
}
```

### Key Data ###
```
{
    "hmacKeyString": (key_bytes), 
    "size": 256
}
```

---

## AES ##
AES provides authenticated encryption through use of HMAC\_SHA1 and AES. The block size is 128 bits.

### Key Hash ###
The key hash components are: ` [aes_key_bytes.length] + [aes_key_bytes] + [hmac_key_bytes] `

### Meta ###
```
{
    ...
    "purpose": "DECRYPT_AND_ENCRYPT", 
    "type": "AES", 
    ...
}
```

### Key Data ###
```
{
    "aesKeyString": (aes_key_bytes), 
    "hmacKey": {
        "hmacKeyString": (hmac_key_bytes), 
        "size": 256
    }, 
    "mode": "CBC", 
    "size": (128|192|256)
}
```

---

## DSA Public Key ##
The digest size is 384 bits. SHA1 is used for the digest.

### Key Hash ###
The key hash components are: ` [leftTrimZero(p).length] + [leftTrimZero(p)] + [leftTrimZero(q).length] + [leftTrimZero(q)] + [leftTrimZero(g).length] + [leftTrimZero(g)] + [leftTrimZero(y).length] + [leftTrimZero(y)] `

### Meta ###
```
{
    ...
    "purpose": "VERIFY", 
    "type": "DSA_PUB",  
    ...
}
```

### Key Data ###
```
{
    "g": (g_bytes), 
    "p": (p_bytes), 
    "q": (q_bytes), 
    "size": 1024, 
    "y": (y_bytes)
}

```

---

## DSA Private Key ##
The digest size is 384 bits. SHA1 is used for the digest.

### Key Hash ###
The key hash components are: ` [leftTrimZero(p).length] + [leftTrimZero(p)] + [leftTrimZero(q).length] + [leftTrimZero(q)] + [leftTrimZero(g).length] + [leftTrimZero(g)] + [leftTrimZero(y).length] + [leftTrimZero(y)] `

### Meta ###
```
{
    ...
    "purpose": "SIGN_AND_VERIFY", 
    "type": "DSA_PUB",  
    ...
}
```

### Key Data ###
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

---

## RSA Public Key ##
Possible digest sizes are 128, 256, 512 or 256 depending on key size and implementation. SHA1 is used for digests

### Key Hash ###
The key hash components are: ` [leftTrimZero(modulus).length] + [leftTrimZero(modulus)] + [leftTrimZero(public_exponent).length] + [leftTrimZero(public_exponent)] `

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

### Key Data ###
```
{
    "modulus": (modulus_bytes), 
    "publicExponent": (exp_bytes), 
    "size": (1024|2048|4096),
    "padding": ("OEAP"|"PKCS")
}
```
Padding is an optional parameter that defaults to ` "OEAP" `

---

## RSA Private Key ##
Possible digest sizes are 128, 256, 512 or 256 depending on key size and implementation. SHA1 is used for digests

### Key Hash ###
The key hash components are: ` [leftTrimZero(modulus).length] + [leftTrimZero(modulus)] + [leftTrimZero(public_exponent).length] + [leftTrimZero(public_exponent)] `

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

### Key Data ###
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
Padding is an optional parameter that defaults to ` "OEAP" `