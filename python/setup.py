from distutils.core import setup

import sys

setup(name='python-keyczar',
      description='Toolkit for safe and simple cryptography',
      author='Arkajit Dey',
      author_email='arkajit.dey@gmail.com',
      url='http://www.keyczar.org/',
      version='0.71b',
      packages=['keyczar'],
      package_dir={'keyczar': 'src/keyczar'},
      requires=['pycrypto (>2.0)'],
)
