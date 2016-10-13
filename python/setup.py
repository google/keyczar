"""
Keyczar is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications. Keyczar supports authentication and encryption with both symmetric and asymmetric keys. Some features of Keyczar include:

* A simple API
* Key rotation and versioning
* Safe default algorithms, modes, and key lengths
* Automated generation of initialization vectors and ciphertext signatures
* Java, Python, and C++ implementations
* International support in Java (Python coming soon)

Keyczar was originally developed by members of the Google Security Team and is released under an Apache 2.0 license.
"""

from setuptools import setup

classifiers = """
Development Status :: 5 - Production/Stable
Intended Audience :: Developers
License :: OSI Approved :: Apache Software License
Programming Language :: Python
Topic :: Security
Topic :: Security :: Cryptography
Topic :: Software Development :: Libraries :: Python Modules
Operating System :: MacOS :: MacOS X
Operating System :: Microsoft :: Windows
Operating System :: Unix
"""

doclines = __doc__.split("\n")

setup(name='python-keyczar',
      description='Toolkit for safe and simple cryptography',
      author='Arkajit Dey',
      author_email='arkajit.dey@gmail.com',
      url='http://www.keyczar.org/',
      version='0.716',
      packages=['keyczar'],
      package_dir={'keyczar': 'src/keyczar'},
      install_requires=['pycrypto>2.0', 'pyasn1'],
      maintainer='Google, Inc.',
      maintainer_email='keyczar-discuss@googlegroups.com',
      license='http://www.apache.org/licenses/LICENSE-2.0',
      platforms=['any'],
      classifiers=filter(None, classifiers.split("\n")),
      long_description=doclines[0],

      # create an executable for the KeyCzar tool
      entry_points={'console_scripts': ['keyczart = keyczar.keyczart:_main_setuptools']},
)
