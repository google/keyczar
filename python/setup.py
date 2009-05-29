from distutils.core import setup

import sys
try:
    from setuptools import setup
    kw = {
        'install_requires': 'pycrypto >= 1.9',
    }
except ImportError:
    from distutils.core import setup
    kw = {}

setup(name='python-keyczar',
      description='Toolkit for safe and simple cryptography',
      author='Arkajit Dey',
      author_email='arkajit.dey@gmail.com',
      url='http://www.keyczar.org/',
      version='0.6b',
      packages=['keyczar'],
      **kw
)
