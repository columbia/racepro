#!/usr/bin/python

from distutils.core import setup

setup(
    name = 'RacePro',
    description = 'RacePro tools',
    author = 'Oren Laadan',
    author_email = 'orenl@cs.columbia.edu',
    package_dir={'': 'src'},
    packages=[''],
    scripts=['src/racepro', 'src/racetest']
)
