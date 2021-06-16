#!/usr/bin/env python
from setuptools import setup

setup(
    name="tap-sftp",
    version="1.0.2",
    description="Singer.io tap for extracting data",
    author="Stitch",
    url="http://singer.io",
    classifiers=["Programming Language :: Python :: 3 :: Only"],
    py_modules=["tap_sftp"],
    install_requires=[
        "singer-python==5.9.0",
        'paramiko==2.6.0',
        'backoff==1.8.0',
        'singer-encodings @ git+https://github.com/Liftitapp/singer-encodings.git#egg=singer-encodings',
        'terminaltables==3.1.0',
        'python-gnupg==0.4.7',
    ],
    extras_require={
        'dev': [
            'ipdb',
            'pylint',
            'nose'
        ]
    },
    entry_points="""
    [console_scripts]
    tap-sftp=tap_sftp:main
    """,
    packages=["tap_sftp"],
    package_data = {
        "schemas": ["tap_sftp/schemas/*.json"]
    },
    include_package_data=True,
)
