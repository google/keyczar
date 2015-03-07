# HMAC Key Format #

HMAC keys are stored in JSON format and consist of the following values:
  * "hmacKeyString": Web-safe Base64-encoded raw HMAC-SHA1 key bytes
  * "size": size of HMAC key in bits

The digest size is 160 bits.

### Key Hash ###
The KeyHash components are: ` key_bytes `

### Meta ###
```
{
    ...
    "purpose": "SIGN_AND_VERIFY", 
    "type": "HMAC_SHA1", 
    ...
}
```

### JSON Representation ###
```
{
    "hmacKeyString": (key_bytes), 
    "size": 256
}
```
### Supported Sizes and Key types ###
#### Java ####
256 bit key size
(Note that this is longer than the block size of SHA1, 160 bits)
#### Python ####
256 bit key size
(Note that this is longer than the block size of SHA1, 160 bits)
#### C++ ####
Supports 160, 224, 256, 384, 512 key sizes when not in compat mode

uses the corresponding SHA1 or SHA2 algorithm for its key size

Also when not in compat mode, the type in the meta data is HMAC and HMAC\_SHA1 is not supported.

Only supports 256 bit key sizes with SHA1 in compat mode
(Note that this is longer than the block size of SHA1, 160 bits)