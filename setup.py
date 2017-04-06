#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
import os

from setuptools import setup

setup(
    name = 'supervisor-iperf',
    version = '0.1',
    py_modules = ['supervisor_iperf'],

    author = 'Pavel Marakhovsky',
    author_email = 'pavel@marakhovsky.com',
    description = 'Helper eventhandlers for iperf3',
    long_description = open(os.path.join(os.path.dirname(__file__), 'README.md')).read(),
    license = 'Apache 2.0',
    keywords = 'iperf3 iperf supervisor',
    url = 'https://github.com/Unatine/supervisor-iperf',
    classifiers = [
        #'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
         'Development Status :: 3 - Alpha',
        # 'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
        'Environment :: Web Environment',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    entry_points = {
        'console_scripts': [
            'supervisor_iperf = supervisor_iperf:main',
        ]
    }
)
