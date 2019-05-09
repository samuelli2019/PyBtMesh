# coding:utf-8

from setuptools import setup

setup(
    name='PyBtMesh',
    version='0.1.3',
    description='Python module for bluetooth mesh',
    author='samuelli2019',
    author_email='lijyigac@gmail.com',
    url='https://github.com/samuelli2019/PyBtMesh',
    packages=['btmesh'],
    requires=["bitstring", "cryptography"],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
