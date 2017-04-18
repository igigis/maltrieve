#!/usr/bin/env python
from distutils.core import setup
from pip.req import parse_requirements

install_reqs = parse_requirements('requirements.txt', session=False)

setup(name='maltrieve',
      version='0.8',
      description="A tool to retrieve malware directly from the source for security researchers.",
      author='Kyle Maxwell + Harry Roberts',
      author_email='maltrieve@midnight-labs.org',
      url='http://maltrieve.org',
      install_requires=[str(ir.req) for ir in install_reqs],
      package_dir={'maltrieve': 'src'},
      packages=['maltrieve'],
      entry_points={'console_scripts': ['maltrieve =  maltrieve:main']})
