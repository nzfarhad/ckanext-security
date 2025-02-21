from setuptools import setup, find_packages

version = '3.0.4'

setup(
    name='ckanext-security',
    version=version,
    description='Various security patches for CKAN',
    long_description='',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords='',
    author='Data.govt.nz',
    author_email='info@data.govt.nz',
    url='https://www.data.govt.nz',
    license='AGPL',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'ckan>=2.11.0',
    ],
    dependency_links=[],
    entry_points="""
    [ckan.plugins]
    security=ckanext.security.plugin:CkanSecurityPlugin
    """,
)
