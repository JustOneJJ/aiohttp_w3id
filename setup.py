# Copyright 2018 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
w3id authentication middleware plugin for aiohttp.
"""

from os import path

# Always prefer setuptools over distutils
from setuptools import setup

# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    "Utility function to read a file called `fname`."
    here = path.abspath(path.dirname(__file__))
    return open(path.join(here, fname), encoding='utf-8').read()

setup(
    name='python3-w3id',
    version='0.1.0',
    author='Justinas V. Daugmaudis',
    author_email='justinas@lt.ibm.com',
    description='w3id authentication middleware plugin for aiohttp',
    long_description=read('README.md'),
    url='https://github.com/justinas-vd/python3-w3id',
    license='Apache-2.0',
    packages=['w3id', 'w3id.oauth2'],
    platforms=['any'],
    install_requires = ['pyjwt', 'python-dateutil', 'aiohttp', 'aiohttp_session'],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3',
    ]
)
