#!/usr/bin/env python
import os
from distutils.core import setup
setup(
    name='goldengate',
    version='0.1',
    description='Golden Gate is a cloud gateway',
    long_description=open(os.path.join(os.path.dirname(__file__), 'README')).read(),
    author='SimpleGeo',
    author_email='nerds@simplegeo.com',
    url='http://github.com/simplegeo/goldengate',

    packages=['goldengate'],
    provides=['goldengate'],
    requires=[
        'gunicorn',
        'eventlet',
        'httplib2',
    ]
)
