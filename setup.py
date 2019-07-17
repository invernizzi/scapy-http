#! /usr/bin/env python

"""
scapy-http: HTTP support for Scapy. Deprecated
"""

from __future__ import print_function

from packaging import version
from setuptools import setup
from setuptools.command.install import install
import os.path
import shutil
import warnings

VERSION = '1.8'

DEPRECATION_MESSAGE = """
Scapy 2.4.3+ has native support for HTTP. It has the same syntax as this package (isn't that nice), plus it packs more features!

Please consider this package as obsolete - long live Scapy!

DEPRECATED! DEPRECATED! DEPRECATED!
"""


class InstallCommand(install):
    """Installation command"""

    def run(self):
        import scapy
        # See README.md
        warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning)  # Soft deprecation
        if version.parse(scapy.VERSION) >= version.parse("2.4.3"):  # Hard deprecation
            # Scapy 2.4.3 already has a http.py file in scapy/layers/
            raise DeprecationWarning("scapy-http cannot be installed on Scapy 2.4.3+ !")
        print('Installing the HTTP layer extension into Scapy...', end='')
        target_path = os.path.join(
            os.path.dirname(scapy.__file__),
            'layers'
        )
        source_path = os.path.join(
            os.path.dirname(__file__),
            'scapy_http/http.py'
        )
        shutil.copy2(source_path, target_path)
        print(' OK')


setup(
    name="scapy-http",
    packages=['scapy_http'],
    version=VERSION,
    description="HTTP-layer support for Scapy",
    install_requires=['scapy'],
    author=['Luca Invernizzi, Steeve Barbeau'],
    author_email=['invernizzi.l@gmail.com'],
    url='https://github.com/invernizzi/scapy-http',
    download_url='https://github.com/invernizzi/scapy-http/tarball/' + VERSION,
    keywords=['http', 'scapy', 'network', 'dissect', 'packets'],
    cmdclass={
        'install': InstallCommand,
    },
    classifiers=[
        'Development Status :: 7 - Inactive'
    ]
)
