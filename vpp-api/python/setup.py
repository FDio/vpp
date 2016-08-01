try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup (name = 'vpp_papi',
       version = '1.1',
       description = 'VPP Python binding',
       author = 'Ole Troan',
       author_email = 'ot@cisco.com',
       #url = 'https://docs.python.org/extending/building',
       test_suite = 'tests',
       packages=['vpp_papi'],
       long_description = '''
VPP Python language binding.
''',)
