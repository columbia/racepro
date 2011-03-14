#!/usr/bin/python

import os
import sys
import shutil
import logging
import argparse
import subprocess
import pdb
__dummy = open('/dev/null', 'r')

def do_exec(cmd, redirect):
    p1 = subprocess.Popen(cmd.split(),
                          stdin=__dummy,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    p2 = subprocess.Popen(['/bin/cat'],
                          stdin=p1.stdout,
                          stdout=redirect,
                          stderr=subprocess.STDOUT)
    p1.stdout.close()
    return p1.wait()

def do_one_test(args, t_name, t_exec):
    if not args.logmask and not args.logflags:
        args.logflags = 'sScrdgp'

    e_record = 'sudo record'
    if args.logmask: e_record += ' -l %s' % args.logmask
    if args.logflags: e_record += ' -f %s' % args.logflags

    e_replay = 'sudo replay -l 15'
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

    if args.quiet:
        redirect = open(path + '.out', 'w')
    else:
        redirect = None

    logging.info('  recording original exceution (twice)')
    if t_pre:
        logging.info('    clean-up before recording...')
        logging.error(t_pre + ' %s' % (path + '.log'))
    logging.info('    1st recording ...')
    cmd = e_record + ' -o %s ./%s' % (path + '.log', t_exec)
    ret = do_exec(cmd, redirect)
    if ret != 0:
        logging.error('failed 1st recording')
        if not args.keepgoing: return False 
    if t_pre:
        logging.info('    clean-up before recording...')
        do_exec(t_pre + ' %s' % (path + '.log'))
    logging.info('    2nd recording ...')
    cmd = e_record + ' -o %s ./%s' % (path + '.log', t_exec)
    ret = do_exec(cmd, redirect)
    if ret != 0:
        logging.error('failed 2nd recording')
        if not args.keepgoing: return False 

    logging.info('  replaying original execution')
    if t_pre:
        logging.info('    clean-up before replaying...')
        cmd = t_pre + ' %s' % (path + '.log')
        do_exec(cmd, redirect)
    logging.info('    replaying ...')
    cmd = e_replay + ' %s' % (path + '.log')
    ret = do_exec(cmd, redirect)
    if ret != 0:
        logging.error('failed original replay')
        if not args.keepgoing: return False

    logging.info('  generating the races')
    cmd = e_racepro + '%s show-races -D -i %s -o %s' % \
        (opts1, path + '.log', path)
    ret = do_exec(cmd, None)
    if ret != 0:
        logging.error('failed to generate races')
        if not args.keepgoing: return False

    logging.info('  testing the races')
    exitiffail = '--exit-on-failed-replay'
    if(args.keepgoing):
        exitiffail = ''
    cmd = e_racepro + \
        ' %s test-races -i %s -o %s %s %s' % \
        (opts1, path + '.log', path, opts2, exitiffail)
    ret = do_exec(cmd, redirect)
    if ret != 0:
        logging.error('failed to test the races (exit %d)' % ret)
        if not args.keepgoing: return False

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
parser.add_argument('-o', '--outdir', dest='outdir', default='/tmp',
                    help='Location where to store the testingd')
parser.add_argument('-q', '--quiet', dest='quiet',
                    action='store_true', default=False,
                    help='If set, redirect stdout/err to a file')
parser.add_argument('-l', '--log-level', dest='logmask', default=None,
                    help='Log mask argument, see arguments.')
parser.add_argument('-f', '--log-flags', dest='logflags', default=None,
                    help='Log mask argument, see record(1) arguments.')
parser.add_argument('-k', '--keep-going', dest='keepgoing', 
                    action='store_true', default=False, 
                    help='Keep going with other logs on divergence of one log')
parser.add_argument('--exec-shell', dest='exec_shell',
                    default=False, action='store_true',
                    help='Execute TEST like shell script (suffix .sh)')
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

if args.exec_shell:
    for t in req_tests:
        if t not in all_tests_d:
            all_tests_l.append([t, t + '.sh'])
            all_tests_d[t] = t + '.sh'

for t in req_tests:
    print('TEST: %s' % t)
    if not do_one_test(args, t, all_tests_d[t]):
        break
