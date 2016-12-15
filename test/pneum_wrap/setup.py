# setup.py (with automatic dependency tracking)
from setuptools import setup

setup(name='pneum_wrap',
      version='1.2',
      description='VPP pneum wrapper',
      author='Klement Sekera',
      author_email='ksekera@cisco.com',
      setup_requires=["cffi>=1.0.0"],
      cffi_modules=["build_pneum_wrap.py:ffibuilder"],
      install_requires=["cffi>=1.0.0"],
      long_description='''VPP pneum wrapper.''',
      )
