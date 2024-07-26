from setuptools import setup

setup(
    name='elixir-dns',
    version='1.0.0',
    description='Elixir is a fast multi-function DNS Enumeration, Subdomain Enumeration and Attack Surface Mapping tool.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/B0lg0r0v/Elixir',
    author='B0lg0r0v',
    author_email='contact@arthurminasyan.com',
    maintainer='B0lg0r0v',
    license='MIT',
    install_requires=[
        'beautifulsoup4',
        'dnspython',
        'requests',
    ],
    packages=[
        'src',
        'src.core',
    ],
    package_data={
        'src': ['list/subdomains.txt'],
    },
    entry_points={
        'console_scripts': [
            'elixir-dns=src.entry:main',
        ],

    },
    platforms=['Unix'],    
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    
    ]   

)