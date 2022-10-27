# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup

import fastentrypoints

dependencies = ["click"]

config = {
    "version": "0.1",
    "name": "validate_hostname",
    "url": "https://github.com/jakeogh/validate-hostname",
    "license": "ISC",
    "author": "Justin Keogh",
    "author_email": "github.com@v6y.net",
    "description": "comprehensive hostname validation",
    "long_description": __doc__,
    "packages": find_packages(exclude=["tests"]),
    "package_data": {"validate_hostname": ["py.typed"]},
    "include_package_data": True,
    "zip_safe": False,
    "platforms": "any",
    "install_requires": dependencies,
    "entry_points": {
        "console_scripts": [
            "validate-hostname=validate_hostname.validate_hostname:cli",
        ],
    },
}

setup(**config)
