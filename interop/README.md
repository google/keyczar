# Interop Testing

The code for interop testing is located in the interop folder.

## Running Interop Tests


Before running the interop tests, build the necessary files. This can
be done by running the "build_all.sh" script from the interop
directory or by building each version

For Python, it will use the current development version and nothing
needs to be built.

For Java, run "mvn package" from the "java/code" directory. The
interop tests will sometimes load the wrong version of the jar since
they are versioned by date and selected by a wildcard character and
only the first one included will be used. This can be fixed by
deleting the targets folder and rebuilding the jars.

For C++, run:

```shell
sh ./tools/swtoolkit/hammer.sh --mode=opt-linux --compat
```

from the "cpp/src" directory.

To run the interop tests, go to the interop directory and execute

```shell
./interop.py
```

To rerun the interop tests using the same keydata as the previous run
(useful for dealing with flaky tests). You can run the interop tests
without creating keys.

```shell
./interop.py --create=n
```

## Writing a new Implementation

### Implementation JSON

For a language to be used with the interop testing infrastructure
there needs to be a command line interface that the infrastructure can
call. This command line interface must be added to the list of
implementations in the "config/implementations.json" file. The format
of this interface is:

```json
{
  "implementationName" : ["../listOfArgs","--needed","to","--call","implementation"],
  ...
}
```

### The command line tool

The command line tool for the implementation will be passed one
command line argument, a JSON string. This JSON string will be a
dictionary of values that will instruct the command line tool what to
do. There will always be a "command" specified in this
dictionary. This attribute will specify the rest of the format of the
JSON string. The three possible values for "command" are "create",
"generate", and "test". These will be discussed in the following
sections.

#### Create

This command causes a keyset to be created. It assumes that the
implementation will run keyczar tool with the given arguments. Each
command listed in keyczartCommands are the arguments for a keyczart
call. The commands should be ran in the order they are listed. The
directories where the keys will be created will be emptied
beforehand. The stdout and stderr will be printed as part of
interop.py. If there is an error, have the command line tool return a
non-zero return code.

Example of parameters for a create command:

```json
{
    "command": "create",
    "keyczartCommands": [
        [
            "create",
            "--name=dsa1024",
            "--location=keys/cpp/dsa1024",
            "--purpose=sign",
            "--asymmetric=dsa"
        ],
        [
            "addkey",
            "--status=primary",
            "--size=1024",
            "--location=keys/cpp/dsa1024"
        ],
        [
            "addkey",
            "--status=primary",
            "--size=1024",
            "--location=keys/cpp/dsa1024"
        ],
        [
            "pubkey",
            "--destination=keys/cpp/dsa1024public",
            "--location=keys/cpp/dsa1024"
        ]
    ]
}
```

####Reading from a Key Set

Key set names need to be constructed in each tool. The correct
formatting of each name is as follows:

```java
keyPath + algorithm + cryptedKeySet + pubKey
```

cryptedKeySet and pubKey are in options and will be blank or not
present if there is no encryption used on the keyset or the key is not
just a public key.

#### Generate

The Generate command will generate data for other implementations to
test. The Generate function will run the designated operation, using
the algorithm and options listed. For example, if the operation
involves signing. The generate function will compute the signature and
pass that into the output. If it is an encryption operation, the
output will be the encrypted data. The possible types of operations
can be found in the "config/operations.json" file, along with the
other options possible for generateOptions. The keys for any given
algorithm can be loaded in from the path resulting from the
concatenation of the "keyPath" and "algorithm" name. To understand
what an individual option does, checking the code of another
implementation is useful. In general, the encoding will specify
whether the output is WebSafeBase64 "encoded" or it is "unencoded" and
the "class" option will specify what kind of keyczar class is used:
either a Crypter or an Encrypter. "testData" is the value of the data
to be encrypted/signed. This will be an ASCII string. If there is an
error that occurs during generation, please print a useful debugging
message and return a non-zero exit code.

Example input:

```json
{
    "algorithm": "dsa1024",
    "command": "generate",
    "generateOptions": {
        "cryptedKeySet": "",
        "encoding": "encoded"
    },
    "keyPath": "keys/cpp",
    "operation": "unversioned",
    "testData": "This is some test data."
}
```

The result from the Generate function is sent to stdout. Be sure that
other forms of logging are disabled or only occur when there is a
failure. Otherwise the JSON will not be able to be read by interop.py.
The format of the JSON has an output parameter that contains the
WebSafeBase64 encoding of the output of the Generate function. Note
that this may be the WebSafeBase64 encoding of an already
WebSafeBase64 encoded output. The only current exception to this
formatting is SignedSessionOperations which in addition to an output
parameter also have a sessionMaterial parameter which contains the
sessionMaterial (all current implementations only output the
sessionMaterial in WebSafeBase64 format, so the WebSafeBase64 format
is not applied again).

Example output:

```json
{
  "output" : "AN7ZKnEAAAAXVGhpcyBpcyBzb21lIHRlc3QgZGF0YS4wLQIUXO1lHO3-X43qIYayDyNR3LNrOjwCFQCmW7NA6qY1tQy83UkTRyySyWfcVw"
}
```

#### Test

The test command should ensure that the output from the generate
command is valid. For encryption operations, this means decrypting the
data and comparing it to the original data. For signing operations,
this means verifying the signature.

The data is similar in format to the generate command. The output is a
json dictionary of values, the output of the Generate
command. "generateOptions" show what options were used to generate the
output. "testOptions" are options that are used the same output from
the generate, but are different ways the data can be verified. For
example, in signing operations, the "class" option can specify to
verify using a "signer" or a "verifier". These options are also listed
in the operations.json file. If the code fails to verify or there is
an error, the test command should return a non-zero exit code along
with some debugging messages to why the test failed (like a stack
trace for instance). If the test command succeeds, the output does not
matter and will not be output by "interop.py".

```json
{
    "algorithm": "dsa1024",
    "command": "test",
    "generateOptions": {
        "cryptedKeySet": "aes128",
        "encoding": "unencoded"
    },
    "keyPath": "keys/cpp",
    "operation": "unversioned",
    "output": {
        "output": "MCwCFHKOubf83Nkn7obGRBWfXoQfm5d5AhRUctSgQJuqMDl-RrQesFLAP57xrA"
    },
    "testData": "This is some test data.",
    "testOptions": {
        "class": "verifier",
        "pubKey": ""
    }
}
```

### Adding Exceptions

In general, all possible combinations of implementations, operations,
algorithms, key sizes, and options will be used. If there is a certain
set of operations/algorithms/options that are not interoperable for
some reason, they can be added to the ignoredTests.json file. The
format for adding an exception is shown in the example below. The
wildcard character ("`*`") means that the ignored test applies for all
possible implementations, algorithms, operations, or options.

The implementation lists the implementation that this affects. This is
for both generate and test.

The operation lists the operations that this affects. This is for both
generate and test.

The algorithms lists the algorithms that this applies to. This is for
both generate and test.

The options list the options that are required. If the option is not
present it will not be constrained. It is a dictionary with names and
lists.

The reason is the reason that these tests are ignored to be displayed
each time the interop tests are run.

```json
{
  "implementation" : ["*"],
  "operation" : ["signedSession"],
  "algorithm" : ["rsa-crypt1024"],
  "options" : {"*" : "*"},
  "reason" : "metadata in signed session is too big to be encrypted by 1024 bit RSA"
}
```
