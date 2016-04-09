from distutils.core import setup, Extension

module1 = Extension('vpp_api',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    include_dirs = ['pneum'],
                    libraries = ['pneum'],
                    library_dirs = ['../../build-root/install-vpp_debug-native/vpp-api/lib64'],
                    sources = ['vpp_papi/pneum_wrap.c'])

setup (name = 'vpp_papi',
       version = '1.0',
       description = 'VPP Python binding',
       author = 'Ole Troan',
       author_email = 'ot@cisco.com',
       #url = 'https://docs.python.org/extending/building',
       packages=['vpp_papi'],
       long_description = '''
VPP Python language binding.
''',
       ext_modules = [module1])
