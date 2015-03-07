# Keyczar Tool #

This command-line tool allows the user to create and manage Keyczar key files. It supports the following commands and flags to allow for easy creation, rotation, and revocation of keys. KeyczarTool is called with a single command and a list of flags of the form ` --flag=value `. Valid commands are: _create, addkey, pubkey, promote, demote, revoke_. Valid flags are : _location, name, size, status, purpose, destination, version, asymmetric crypter_. Optional flags are in _italics_. The notation (a|b|c) means "a", "b", and "c" are the valid choices

## Standalone Jar ##

A standalone [KeyczarTool Jar](http://code.google.com/p/keyczar/downloads/) compiled for Java 1.6 is available for download.

## Usage ##

  * create --location=/path/to/keys --purpose=(crypt|sign) _--name="A name" --asymmetric=(dsa|rsa)_
> Creates a new, empty key set in the given location.
> This key set must have a purpose of either "crypt" or "sign"
> and may optionally be given a name. The optional asymmetric
> flag will generate a public key set of the given algorithm.
> The "dsa" asymmetric value is valid only for sets with "sign" purpose.
> with the given purpose.

  * addkey --location=/path/to/keys _--status=(active|primary) --size=size --crypter=crypterLocation --padding=(OEAP|PKCS)_
> Adds a new key to an existing key set. Optionally
> specify a purpose, which is active by default. Optionally
> specify a key size in bits. Also optionally specify the
> location of a set of crypting keys, which will be used to
> encrypt this key set. Padding is an optional parameter to specify the type of rsa padding to be used and it is only available in Java.

  * pubkey --location=/path/to/keys --destination=/destination
> Extracts public keys from a given key set and writes them
> to the destination. The "pubkey" command Only works for
> key sets that were created with the "--asymmetric" flag.

  * promote --location=/path/to/keys --version=versionNumber
> Promotes the status of the given key version in the given
> location. Active keys are promoted to primary (which demotes
> any existing primary key to active). Keys scheduled for
> revocation are promoted to be active.

  * demote --location=/path/to/keys --version=versionNumber
> Demotes the status of the given key version in the given
> location. Primary keys are demoted to active. Active keys
> are scheduled for revocation.

  * revoke --location=/path/to/keys --version=versionNumber
> Revokes the key of the given version number.
> This key must have been scheduled for revocation by the
> promote command. WARNING: The key will be destroyed.