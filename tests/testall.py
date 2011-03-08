#!/usr/bin/python

import os
import sys
import shutil
import logging
import argparse
import subprocess
import pdb

def do_exec(cmd):
    return subprocess.call(cmd.split())

def do_one_test(args, t_name, t_exec):
    e_record = 'sudo record'
    e_replay = 'sudo replay'
    e_racepro = '../src/racepro'

    logging.info('Processing test: %s' % (t_name))

    pdir = args.outdir + '/' + t_name
    path = args.outdir + '/' + t_name + '/out'

    t_pre = '%s.pre' % t_name
    if not os.access(t_pre, os.R_OK):
        t_pre = None
    t_test = '%s.test' % t_name
    if not os.access(t_test, os.R_OK | os.X_OK):
        t_test = None

    opts1 = ''
    if args.debug: opts1 += ' -d'
    if args.verbose: opts1 += ' -v'

    opts2 = ''
    if t_pre: opts2 += ' --script-pre=./%s' % t_pre
    if t_test: opts2 = ' --script-test=./%s' % t_test

    logging.info('  output in directory %s' % (pdir))
    if os.access(pdir, os.R_OK):
        shutil.rmtree(pdir)
    os.mkdir(pdir)

    logging.info('  recording original exceution (twice)')
    if t_pre:
        logging.info('    clean-up before recording...')
        logging.error(t_pre + ' %s' % (path + '.log'))
    logging.info('    1st recording ...')
    ret = do_exec(e_record + ' -l 15 -o %s ./%s' % (path + '.log', t_exec))
    if ret != 0:
        logging.error('failed 1st recording')
        return False
    if t_pre:
        logging.info('    clean-up before recording...')
        do_exec(t_pre + ' %s' % (path + '.log'))
    logging.info('    2nd recording ...')
    ret = do_exec(e_record + ' -l 15 -o %s ./%s' % (path + '.log', t_exec))
    if ret != 0:
        logging.error('failed 2nd recording')
        return False

    logging.info('  replaying original execution')
    if t_pre:
        logging.info('    clean-up before replaying...')
        do_exec(t_pre + ' %s' % (path + '.log'))
    logging.info('    replaying ...')
    ret = do_exec(e_replay + ' %s' % (path + '.log'))
    if ret != 0:
        logging.error('failed original replay')
        return False

    logging.info('  generating the races')
    ret = do_exec(e_racepro + ' %s show-races -i %s -o %s' %
                  (opts1, path + '.log', path))
    if ret != 0:
        logging.error('failed to generate races')
        return False

    logging.info('  testing the races')
    ret = do_exec(e_racepro + ' %s test-races -i %s -o %s %s --exit-on-failed-replay' %
                  (opts1, path + '.log', path, opts2))
    if ret != 0:
        logging.error('failed to test the races %d' % ret)
        return False

    return True

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
parser.add_argument('-o', '--outdir', dest='outdir',
                    default='/tmp')
parser.add_argument('tests', metavar='TEST', nargs='*')

args = parser.parse_args()

log = logging.ERROR
if args.verbose: log = logging.INFO
if args.debug: log = logging.DEBUG
logging.basicConfig(level=log, stream=sys.stdout)

all_tests = list()
with open('tests.list', 'r') as file:
    all_tests_l = [ l.split() for l in file ]
    all_tests_d = dict(all_tests_l)

req_tests = args.tests if args.tests else [n for n ,t in all_tests_l]

for t in req_tests:
    if not do_one_test(args, t, all_tests_d[t]):
        break
