#!/usr/bin/env python
import os
from setuptools import setup, find_packages
setup(
    name='goldengate',
    version='0.1',
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
