#!/usr/bin/python

from distutils.core import setup

setup(
    name = 'RacePro',
    description = 'RacePro tools',
    author = 'Oren Laadan',
    author_email = 'orenl@cs.columbia.edu',
    packages=['racepro', 'racepro.mutator'],
    scripts=['scripts/racepro', 'scripts/racetest', 'scripts/isolate',
             'scripts/raceshow'],
    requires=['networkx', 'argparse', 'scribe', 'pygraphviz']
)
