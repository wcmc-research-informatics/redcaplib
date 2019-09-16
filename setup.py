from setuptools import setup, find_packages
import os

LIBNAME = 'redcaplib'

def read_requirements():
    """Parse requirements from requirements.txt."""
    reqs_path = os.path.join('.', 'requirements.txt')
    with open(reqs_path, 'r') as f:
        requirements = [line.rstrip() for line in f]
    return requirements

setup(name=LIBNAME,
      packages=find_packages(),
      install_requires=read_requirements(),
      zip_safe=False)

