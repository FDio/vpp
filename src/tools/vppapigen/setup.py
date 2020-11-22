from setuptools import setup


def readme():
    with open('VPPAPI.md') as f:
        return f.read()


def version():
    with open('VERSION') as f:
        return f.read()

setup(
        name='vppapigen',
        version=version(),
        description='VPP API file parser/generator',
        author='Ole Troan',
        author_email='ot@cisco.com',
        url='https://wiki.fd.io/view/VPP',
        license='Apache-2.0',
        long_description=readme(),
        long_description_content_type='text/markdown',
        classifiers=[
            'Framework :: FD.io VPP',
            'License :: OSI Approved :: Apache 2',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
        ],
        zip_safe=False,
        include_package_data=True,
        # bug https://github.com/pypa/packaging/issues/107
        #  python_requires = '>= 3.5'
        packages=['vppapigen'],
        # package_dir={'vppapigen': 'vppapigen'},
        install_requires=[
            'ply >= 3.11',
            ],

        entry_points={
            'console_scripts': [
                'vppapigen = vppapigen.vppapigen:cli',
                'generate_json = generate_json:cli'
            ],
            'vppapigen.emitters': ['C = vppapigen.vppapigen_c',
                                   'CRC = vppapigen.vppapigen_crc',
                                   'JSON = vppapigen.vppapigen_json',
                                   ]
        },

)
