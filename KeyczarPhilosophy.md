# Keyczar Design Philosophy #

Keyczar's goal is to make it easier to safely use cryptography. Developers should not be able to inadvertently expose key material, use weak key lengths or deprecated algorithms, or improperly use cryptographic modes. Keyczar supports sets of multiple key versions that allow the programmer to easily rotate and retire keys.

## Guiding Principles ##

Some guiding design principles of Keyczar are that:

  * All output will be signed by default.
  * All output and key formats will be open and simple to extend.
  * Appropriate algorithms and reasonable key lengths will be used by default.
  * Keys can be updated without making changes to source code.
  * Raw key material will not be visible through the programmer API.

## Non-Goals ##

Keyczar is not designed to be a general-purpose crypto library or PKI, and in fact some applications it will not perform well. See the NonGoals for more explanation.