# Key Metadata #

Each set of keys has its own metadata consisting of the following:

  * A string-valued name
  * A KeyPurpose
  * A KeyType
  * A set of KeyVersion values

## JSON Representation ##

KeyMetadata values are stored in JSON format with fields of the following names:
  * "name": A String name
  * "pupose": The JSON representation of a KeyPurpose value
  * "type": The JSON representation of a KeyType value
  * "encrypted": A Boolean value indicating whether the keys contained in this set are encrypted. This encryption can be done using another keyczar key set or using PBE.
  * "versions": The JSON representation of an array of KeyVersion values

The JSON format is as follows:
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