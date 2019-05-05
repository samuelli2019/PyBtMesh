# coding:utf-8

from setuptools import setup
# or
# from distutils.core import setup

setup(
    name='PyBtMesh',
    version='0.1',
    description='Python module for bluetooth mesh',
    author='Samuel Li',
    author_email='lijyigac@gmail.com',
    url='https://github.com/samuelli2019/PyBtMesh',
    packages=['btmesh'],
    requires=["bitstring", "cryptography"],
)
