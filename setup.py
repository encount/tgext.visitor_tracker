from setuptools import setup, find_packages

version = '0.1.0'

setup(
    name='tgext.visitor_tracker',
    version=version,
    packages=find_packages(exclude=['ez_setup']),

    # Project uses reStructuredText, so ensure that the docutils get
    # installed or upgraded on the target machine
    install_requires=[
        'TurboGears2 >= 2.2.0',
        #'repoze.who>=2.1b1'
    ],
    include_package_data=True,
    package_data={
        # If any package contains *.txt or *.rst files, include them:
        '': ['*.txt', '*.rst', '*.md'],
    },

    # metadata for upload to PyPI
    author='Martin Thorsen Ranang',
    author_email='mtr@ranang.org',
    description='A TurboGears extension to track visitors.',
    license='GPL',
    namespace_packages=['tgext'],
    keywords='tgext visitor identification plugin',
    url='https://github.com/OnLive/tgext.visitor_tracker',
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
    ],
    entry_points="""
    # -*- Entry points: -*-
    """,
)
