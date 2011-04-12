#!/usr/bin/python

import sys
import logging
import argparse

from racepro import racetest

desc = 'Run through Racepro tests'
parser = argparse.ArgumentParser(description=desc)
parser.add_argument('-d', '--debug', dest='debug',
                    action='store_true', default=False,
                    help='Increase debug vebosity')
parser.add_argument('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Increase vebosity level')
parser.add_argument('-a', '--all', dest='all',
                    action='store_true', default=True)
parser.add_argument('-o', '--outdir', dest='outdir', default=None,
                    help='Location where to store the testingd')
parser.add_argument('-q', '--quiet', dest='quiet',
                    action='store_true', default=False,
                    help='If set, redirect stdout/err to a file')
parser.add_argument('-j', '--jailed', dest='jailed',
                    action='store_true', default=False,
                    help='Run the test in a jailed environment')
parser.add_argument('-l', '--log-level', dest='logmask', default=None,
                    help='Log mask argument, see arguments.')
parser.add_argument('-f', '--log-flags', dest='logflags', default=None,
                    help='Log mask argument, see record(1) arguments.')
parser.add_argument('-k', '--keep-going', dest='keepgoing', 
                    action='store_true', default=False, 
                    help='Keep going with other logs on divergence of one log')
parser.add_argument('-e', '--exec', dest='program',
                    default=False, action='store_true',
                    help='Execute TEST program(s) (and TEST.{pre,post,test})')
parser.add_argument('tests', metavar='TEST', nargs='*')

args = parser.parse_args()

log = logging.ERROR
if args.verbose: log = logging.INFO
if args.debug: log = logging.DEBUG
logging.basicConfig(level=log, stream=sys.stdout)

all_tests = list()
with open('tests.list', 'r') as file:
    all_tests_l = [ l.split() for l in file if l.strip() and l[0] != '#' ]
    all_tests_d = dict(all_tests_l)

req_tests = args.tests if args.tests else [n for n ,t in all_tests_l]

if args.program:
    for t in req_tests:
        if t not in all_tests_d:
            all_tests_l.append([t, t])
            all_tests_d[t] = t

if not args.outdir:
    args.outdir = '/persist'

tests = [ (t, all_tests_d[t]) for t in req_tests ]
racetest.do_all_tests(args, tests)
