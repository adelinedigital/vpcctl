#!/usr/bin/env python

from setuptools import setup, find_packages
setup(
    name = "vpcctl",
    version = "0.1",
    packages = find_packages(),
    scripts = ['bin/vpcctl.py', 'bin/gencloudinit.py'],
    install_requires = ['boto', 'ipcalc', 'pyyaml'],
    author = "Jon M. Skelton",
    author_email = "jskelton@adelinedigital.com",
    description = "AWS VPC initialization utility",
    license = "MIT",
    keywords = "AWS VPC vpcctl",
    url = "https://github.com/adelinedigital/vpcctl",
)
