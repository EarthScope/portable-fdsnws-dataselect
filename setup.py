"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

from __future__ import (print_function)

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
from distutils import log

# To use a consistent encoding
from codecs import open
from os import path
import sys

module_name = 'portable_fdsnws_dataselect'

# Generate version string from version tuple in server code
import importlib
server = importlib.import_module(module_name)
version = '%d.%d.%d' % (server.version[0], server.version[1], server.version[2])

here = path.abspath(path.dirname(__file__))

# Get the long description from the description.rst file
with open(path.join(here, 'description.rst'), encoding='utf-8') as f:
    long_description = f.read()

def custom_command(subclass):
    orig_run = subclass.run

    def custom_run(self):
        # Check that this version of python is OK
        if sys.version_info < (2,7):
            sys.exit('Sorry, Python versions earlier than 2.7 are not supported')
        orig_run(self)
        self.announce(
'''###########################################
Portable fdsnws-dataselect has been installed.  To get started follow these steps:

1) Generate a sample server configuration file with:

$ portable-fdsnws-dataselect -s > server.ini

2) Edit the server.ini file to specify the database file and other settings.

3) Run the server with:

$ portable-fdsnws-dataselect server.ini

###########################################''', level=log.INFO)

    subclass.run = custom_run
    return subclass

@custom_command
class CustomDevelopCommand(develop):
    pass

@custom_command
class CustomInstallCommand(install):
    pass

setup(
    name='portable-fdsnws-dataselect',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=version,

    description='A portable fdsnws-dataselect/1 server',
    long_description=long_description,

    # The project's main homepage.
    url='https://iris-edu.github.io/portable-fdsnws-dataselect/',

    # Author details
    author='IRIS DMC',
    author_email='software-owner@iris.washington.edu',

    # Choose your license
    license='LGPL 3.0',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Scientific/Engineering :: Physics',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    # What does your project relate to?
    keywords='FDSN webservice IRIS miniSEED',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=[module_name], #find_packages(exclude=['contrib', 'docs', 'tests']),

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[],

    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.
    package_data={
        module_name: ['docs/index.html', 'docs/help.html', 'docs/style.css',
                      'docs/application.wadl', 'example/server.ini'],
    },

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
            'portable-fdsnws-dataselect=%s.server:main'%(module_name),
        ],
    },

    cmdclass={
        'develop': CustomDevelopCommand,
        'install': CustomInstallCommand,
    },
)
