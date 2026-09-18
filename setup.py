from importlib.machinery import SourceFileLoader

from setuptools import find_packages, setup

version = SourceFileLoader('version', 'stpmex/version.py').load_module()

install_requires = [
    'cryptography>=3.0,<46',
    'clabe @ git+https://github.com/Elebve/clabe-python.git@main',
    'cuenca-validations>=2.1.46',
    'pydantic>=2.10.3',
    'pydantic-extra-types>=2.10.0',
    'azure-identity>=1.15.0',
    'azure-keyvault-keys>=4.8.0',
    'requests>=2.25',
    'workalendar>=16.1.0,<17.0.0',
]


with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='stpmex',
    version=version.__version__,
    author='Cuenca',
    author_email='dev@cuenca.com',
    description='Client library for stpmex.com',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Elebve/stpmex-python',
    packages=find_packages(),
    include_package_data=True,
    package_data=dict(stpmex=['py.typed']),
    python_requires='>=3.9',
    install_requires=install_requires,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
