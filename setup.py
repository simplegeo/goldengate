#!/usr/bin/env python
import os
from setuptools import setup, find_packages

PKG="goldengate"
__VERSION_FILE = os.path.join(PKG, '_version.py')
__VERSION_LOCALS={}
execfile(__VERSION_FILE, __VERSION_LOCALS)

if '__version__' not in __VERSION_LOCALS:
    raise RuntimeError("No __version__ defined in in %s." % __VERSION_FILE)

version = str(__VERSION_LOCALS['__version__'])


setup(
    name=PKG,
    version=version,
    description='Golden Gate is a cloud gateway',
    long_description=open(os.path.join(os.path.dirname(__file__), 'README')).read(),
    author='SimpleGeo',
    author_email='nerds@simplegeo.com',
    url='http://github.com/simplegeo/goldengate',

    packages=find_packages(),
    provides=['goldengate'],
    install_requires=[
        'httplib2',
    ],
    entry_points = {
        'console_scripts': [
            'gg-new-credentials = goldengate:generate_credentials',
        ]
    },
    tests_require = [
        'unittest2',
    ],
    test_suite='unittest2.collector',
)
