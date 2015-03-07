# AES Keys #
AES provides authenticated encryption through use of HMAC\_SHA1 and AES.

AES keys consist of the following fields:
  * "mode": A [CipherMode](CipherMode.md). Currently "CBC" is the only mode supported.
  * "aesKeyString": A WebSafeBase64 representation of the raw AES key bytes.
  * "hmacKey": A JSON representation of an HmacKey used to sign ciphertexts.

The block size is 128 bits.

### Key Hash ###
The KeyHash components are: ` [aes_key_bytes.length] + [aes_key_bytes] + [hmac_key_bytes] `

### Meta ###
```
{
    ...
    "purpose": "DECRYPT_AND_ENCRYPT", 
    "type": "AES", 
    ...
}
```
## Example JSON Representation ##
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
### Supported Sizes and Key types ###
Defaults to 128 for all versions
128, 192, 256 bit key sizes supported across all versions