

# Keyczar C++ for Developers #

## Implementing a new Reader ##

A new reader would be useful for reading keys and metadata from a new support
or for being stored under a different format.

` Keyczar::Read() ` ([keyczar.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar.h)) initially expects string locations and
automatically instanciates a [KeysetFileReader](http://keyczar.googlecode.com/git/cpp/src/keyczar/rw/keyset_file_reader.h) object. However its ` Read() `
method is overloaded and also accepts ` Reader ` ([keyset\_reader.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/rw/keyset_reader.h)) objects,
so it is possible to use new readers (for example [KeysetEncryptedFileReader](http://keyczar.googlecode.com/git/cpp/src/keyczar/rw/keyset_encrypted_file_reader.h) is
used exactly like this).

## Implementing a new Writer ##

The main reason for implementing a new writer would be the need to create
and update metadata and keys on a new support or represented in a different
format. Note: in this case it would also be necessary to modify [keyczart](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczart.cc). Hopefully
keyczart relies on KeyczarTool ([keyczar\_tool.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczar_tool.h)) which is designed to
be generic and instanciate its readers and writers through a factory. The steps
for creating a new working writer would be:

  1. Implement a new writer inheriting from ` KeysetWriter ` ([keyset\_writer.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/rw/keyset_writer.h))
  1. Update the ` enum ` type inside [keyczar\_tool.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczar_tool.h) to accept this new ` LocationType `.
  1. Update keyczart [keyczart.cc](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczart.cc) to support this new writer there is an hidden option ` --form ` dedicated to this purpose.

## Supporting a new architecture ##

For supporting a new architecture e.g. Win it would be necessary to
accomplish the following steps:

  * Update the build scripts [src/main.scons](http://keyczar.googlecode.com/git/cpp/src/main.scons), [src/keyczar/build.scons](http://keyczar.googlecode.com/git/cpp/src/base/build.scons), [swtoolkit/site\_scons/site\_init.py](http://keyczar.googlecode.com/git/cpp/src/tools/swtoolkit/site_scons/site_init.py) and add a new ` target_platform_xxx ` into [swtoolkit/site\_scons/site\_tools](http://code.google.com/p/keyczar/source/browse/trunk#trunk/cpp/src/tools/swtoolkit/site_scons/site_tools).
  * Most compatibility/portability issues will likely located into [base directory](http://code.google.com/p/keyczar/source/browse/trunk#trunk/cpp/src/keyczar/base). Update the architecture dependent files. The corresponding [Chromium base/ directory](http://src.chromium.org/viewvc/chrome/branches/chrome_official_branch/src/base/) might help for this task.
  * Maybe few others modifications would be needed in [src/keyczar/](http://keyczar.googlecode.com/git/cpp/src/#src/keyczar), likely [here](http://keyczar.googlecode.com/git/cpp/src/keyczar/openssl/rand.cc).
  * Read the next section.

## Implementing a new crypto backend ##

If one had to port this code to Win it would probably make sense to use
MS CryptoAPI or CNG to implement the cryptographic operations. Roughly, what
would then be required would be to implement a new subdirectory keyczar/capi/,
for replacing the default implementation provided by [keyczar/openssl/](http://code.google.com/p/keyczar/source/browse/trunk#trunk/cpp/src/keyczar/openssl).

Then the factory methods implemented inside ` CryptoFactory ` (see
[crypto\_factory.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/crypto_factory.h)) would have to be updated. The switch between the
implementations could then be operated at compile time by defines or at execution
by implementing a ` switch(){} `.

For more insights on this design read the comments inside [key.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/key.h).

If the cryptographic library has special steps for initializing the random
number engine, implement what is required inside a ` RandImpl::Init() `
([rand\_impl.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/rand_impl.h)) method and be sure to call it before any cryptographic
operation using random numbers has to be performed. For example see
[run\_all\_unittests.cc](http://keyczar.googlecode.com/git/cpp/src/keyczar/run_all_unittests.cc) and [rand.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/openssl/rand.h) for how this
initialization is implemented and should be called.


## Generating key sets of reference ##

[testdata\_gen](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/testdata_gen.cc) is used for generating the content of the
subdirectory [data](http://code.google.com/p/keyczar/source/browse/trunk#trunk/cpp/src/keyczar/data). This code needs to be updated each time a new
cryptographic algorithm is implemented or modified.


## Advanced use ##

### KeyczarTool ###

It could be useful to use ` KeyczarTool ` ([keyczar\_tool.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/keyczar_tool.h)) for something else
than for implementing ` keyczart `. For example ` testdata_gen `
([testdata\_gen.cc](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar_tool/testdata_gen.cc)) sucessfully use it for generating all the key sets
of reference.

### Keyczar ###

A ` Keyczar ` ([keyczar.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyczar.h)) subclass can directly be instanciated with a ` Keyset `
(keyczar/keyset.h) object as argument. Likewise it is possible to access the
key set of a ` Keyczar ` instance by calling the ` keyset() ` method.

### Key sets writers observers ###

[Observers](http://keyczar.googlecode.com/git/cpp/src/base/observer_list.h) are used for signaling [key set writers](http://keyczar.googlecode.com/git/cpp/src/keyczar/rw/keyset_writer.h) that the in-memory key set has been updated and that these changes should be written. _FIXME_.


## Code development ##

### C++ Style ###

This project use [this style guide](http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml) for all C++ code.


### Exceptions ###

C++ exceptions are not used for this project. The source code is compiled
with -fno-exceptions. For a rationale read [this page](http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml#Exceptions)



### Base directory [src/keyczar/base/](http://keyczar.googlecode.com/git/cpp/src/keyczar/#keyczar/base) ###

  * There are two kinds of asserts ` CHECK() ` and ` DCHECK() ` (see [logging.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/base/logging.h)). Both are fatals but only ` CHECK ` is triggered once the code is compiled with ` mode=opt-linux `. ` DCHECK ` is triggered only during debug mode. As principle this project tries to avoid fatal interruptions during ` optimized ` mode execution. So the preferred way of handling errors is by returning NULL or false values. On irrecoverable errors however ` CHECK ` can be used.
  * ` scoped_ptr ` (see [scoped\_ptr.h](http://keyczar.googlecode.com/git/cpp/src/base/keyczar/scoped_ptr.h)) and ` scoped_refptr ` (see [ref\_counted.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/base/ref_counted.h)) are used for managing pointers. Altough multiple references should be avoided, ` Key ` objects ([key.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/key.h)) are managed through ` scoped_refptr ` mostly because a ` Keyset ` ([keyset.h](http://keyczar.googlecode.com/git/cpp/src/keyczar/keyset.h)) must maintains two references on each key.