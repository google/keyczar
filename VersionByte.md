# Version Byte (Keyczar 0.6b) #

The first byte of all Keyczar output is an unsigned byte representing the version of Keyczar that generated the output. Currently, the version byte is 0. All other values are reserved for future versions.
  * **0**: Currently the default output version.
  * **1-255**: Reserved for future versions.

# Version Byte (Keyczar 0.5b) #

For the initial release of Keyczar, the version byte was 1.

  * **0**: Reserved
  * **1**: The version byte for Keyczar 0.5b
  * **2-255**: Reserved for future versions.