# Key Versions #

Each KeyMetadata will contain a list of KeyVersion values.

## JSON Representation ##

The JSON representation of a KeyVersion will have the following values:
  * "status": The JSON representation of a KeyStatus
  * "versionNumber": A postive integer version number, this specifies the name of key file
  * "exportable": A boolean value, originally intended for protecting exports from keyczar, but is currently unused by keyczar

Example:
```
{
  "versionNumber" : 1,
  "status" : "ACTIVE",
  "exportable" : false
}
```