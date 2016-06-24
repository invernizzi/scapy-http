from setuptools import setup
from distutils.command.install import install
import os.path
import shutil
import sys

VERSION = '1.8'
scapy_name = 'scapy-python3' if sys.version_info.major==3 else 'scapy'


def install_into_scapy(a):
    print('Installing the HTTP layer extension into Scapy...')
    import scapy
    target_path = os.path.join(
        os.path.dirname(scapy.__file__),
        'layers'
    )
    source_path = os.path.join(
        os.path.dirname(__file__),
        'scapy_http/http.py'
    )
    shutil.copy2(source_path, target_path)
    print('done!')


install.sub_commands.append(('install_into_scapy', install_into_scapy))

setup(
    name="scapy-http",
    packages=['scapy_http'],
    version=VERSION,
    description="HTTP-layer support for Scapy",
    install_requires=[scapy_name],
    author=['Luca Invernizzi, Steeve Barbeau'],
    author_email=['invernizzi.l@gmail.com'],
    url='https://github.com/invernizzi/scapy-http',
    download_url='https://github.com/invernizzi/scapy-http/tarball/' + VERSION,
    keywords=['http', 'scapy', 'newtork', 'dissect', 'packets']
)
