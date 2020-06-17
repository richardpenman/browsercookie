import sys
import os
from distutils.core import setup

def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()

setup(
    name='browsercookie', 
    version='0.7.7',
    packages=['browsercookie'],
    package_dir={'browsercookie' : '.'}, # look for package contents in current directory
    author='Richard Penman',
    author_email='richard.penman@gmail.com',
    description='Loads cookies from your browser into a cookiejar object so can download with urllib and other libraries the same content you see in the web browser.',
    long_description=read('README.rst'),
    url='https://github.com/richardpenman/browsercookie',
    install_requires=['pycryptodome', 'keyring', 'lz4'],
    license='lgpl'
)
