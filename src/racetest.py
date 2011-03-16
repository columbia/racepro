#!/usr/bin/python

import os
import sys
import shutil
import logging
import argparse
import subprocess
import pdb

from itertools import *

import execute

_dummy = open('/dev/null', 'r')

def _exec(cmd, redirect=None):
    p1 = subprocess.Popen(cmd.split(),
                          stdin=_dummy,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    p2 = subprocess.Popen(['/bin/cat'],
                          stdin=p1.stdout,
                          stdout=redirect,
                          stderr=subprocess.STDOUT)
    p1.stdout.close()
    return p1.wait()

def _sudo(cmd, redirect=None):
    if os.geteuid() != 0:
        cmd = 'sudo ' + cmd
    return _exec(cmd, redirect)

def _record(args, logfile=None, opts=''):
    if not logfile:
        logfile = args.path + '.log'
    with execute.open(root=args.root, jailed=args.jailed,
                      chroot=args.chroot, scratch=args.scratch,
                      persist=args.pdir) as exe:
        if args._pre:
            logging.info('    clean-up before recording...')
            cmd = args._pre \
                if os.path.isabs(args._pre) \
                else './' + args._pre
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect,)

        logging.info('    recording ...')
        cmd = args._run if os.path.isabs(args._run) else './' + args._run
        cmd = args.record + ' -o %s %s %s' % (opts, logfile, cmd)
        ret = exe.execute(cmd.split(), notty=True,
                          stdin=_dummy, stdout=args.redirect)

        if args._post:
            logging.info('    clean-up after recording...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect)

        if ret != 0:
            logging.error('failed 1st recording')
            return False

        return True

def _replay(args, logfile=None, opts=''):
    if not logfile:
        logfile = args.path + '.log'
    with execute.open(root=args.root, jailed=args.jailed,
                      chroot=args.chroot, scratch=args.scratch,
                      persist=args.pdir) as exe:
        if args._pre:
            logging.info('    clean-up before replaying...')
            cmd = args._pre \
                if os.path.isabs(args._pre) \
                else './' + args._pre
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r != 0:
                logging.error('failed pre-script (exit %d)' % r)
                return False

        logging.info('    replaying ...')
        cmd = args.replay + ' %s %s' % (opts, logfile)
        ret = exe.execute(cmd.split(), notty=True,
                          stdin=_dummy, stdout=args.redirect)
        if ret != 0:
            logging.error('failed original replay (exit %d)' % ret)

        if args._post:
            logging.info('    clean-up after replaying...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r != 0:
                logging.error('failed post-script (exut %d)' % r)

        return True if ret == 0 else False

def _replay2(args, logfile, verbose, opts=''):
    if not logfile:
        logfile = args.path + '.log'
    with execute.open(root=args.root, jailed=args.jailed,
                      chroot=args.chroot, scratch=args.scratch,
                      persist=args.pdir) as exe:
        if args._pre:
            logging.info('    clean-up before replaying...')
            cmd = args._pre \
                if os.path.isabs(args._pre) \
                else './' + args._pre
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r > 0:
                logging.error('failed pre-script (exit %d)' % r)
                print(verbose + 'bad exit code from pre-script: %d' % r)
                return False

        logging.info('    replaying ...')
        cmd = args.replay + ' %s %s' % (opts, logfile)
        ret = exe.execute(cmd.split(), notty=True,
                          stdin=_dummy, stdout=args.redirect)
        if ret == 35:
            print(verbose + 'replay deadlock')
        elif ret > 0:
            print(vserbose + 'replay failure (exit %d)' % ret)
        else:
            print(verbose + 'replay completed')

        if ret == 0 and args._test:
            logging.info('    running test script...')
            cmd = args._test \
                if os.path.isabs(args._test) \
                else './' + args._test
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r == 2:
                print(verbose + 'BUG REPRODUCED')
                ret = 0
            elif r != 0:
                print(verbose + 'bad exit code from test-script: %d' % r)
                ret = r
            else:
                print(verbose + 'BUG not triggered')
                ret = 0
        elif r == 0:
            print(verbose + 'BUG replayed but not tested')

        if args._post:
            logging.info('    clean-up after replaying...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r > 0:
                logging.error('failed post-script (exit %d)' % r)
                print(verbose + 'bad exit code from post-script: %d' % r)

    return True if ret == 0 else False

def _findraces(args, opts):
    cmd = args.racepro + '%s show-races -i %s -o %s' % \
        (opts, args.path + '.log', args.path)
    ret = _sudo(cmd)
    if ret != 0:
        logging.error('failed to generate races')
        return False
    return True

def _testraces(args):

    for n in count(1):
        logfile = '%s.%d.log' % (args.path, n)
        if not os.access(logfile, os.R_OK):
            break
        v = 'RACE %d: ' % n
        o = '-c %d' % args.timeout
        ret = _replay2(args, logfile, v, opts=o)
        if ret != 0 and not args.keepgoing:
            return False
    return True

def do_one_test(args, t_name, t_exec):
    if args.chroot and not os.access(args.chroot, os.R_OK | os.X_OK):
        os.mkdir(args.chroot)

    if args.scratch and os.access(args.scratch, os.F_OK):
        ret = _sudo('rm -rf %s' % args.scratch)
        os.mkdir(args.scratch)

    if not args.logmask and not args.logflags:
        args.logflags = 'sScrdgp'

    args.record = 'record'
    if args.logmask: args.record += ' -l %s' % args.logmask
    if args.logflags: args.record += ' -f %s' % args.logflags
    if args.initproc in args: args.record += ' -i'

    args.replay = 'replay -l 15'
    if args.initproc in args: args.replay += ' -i'

    args.racepro = 'racepro'

    logging.info('Processing test: %s' % (t_name))

    args.pdir = args.outdir + '/' + t_name
    args.path = args.outdir + '/' + t_name + '/out'

    if 'run' not in args:
        args._run = '%s' % t_exec
    if 'test' not in args:
        args._test = '%s.test' % t_name
    if 'pre' not in args:
        args._pre = '%s.pre' % t_name
    if args._pre and not os.access(args._pre, os.R_OK | os.X_OK):
        args._pre = None
    if 'post' not in args:
        args._post = '%s.post' % t_name
    if args._post and not os.access(args._post, os.R_OK | os.X_OK):
        args._post = None

    opts = ''
    if args.debug: opts += ' -d'
    if args.verbose: opts += ' -v'

    logging.info('  output in directory %s' % args.pdir)
    if os.access(args.pdir, os.R_OK):
        _sudo('rm -rf %s' % args.pdir)
    _sudo('mkdir -p %s' % args.pdir)

    if args.quiet:
        args.redirect = open(args.path + '.out', 'w')
    else:
        args.redirect = None

    logging.info('  recording original exceution (twice)')
    if not _record(args):
        return True if args.keepgoing else False
    if not _record(args):
        return True if args.keepgoing else False

    logging.info('  replaying original execution')
    if not _replay(args):
        return True if args.keepgoing else False

    logging.info('  generating the races')
    if not _findraces(args, opts):
        return True if args.keepgoing else False

    logging.info('  testing the races')
    if not _testraces(args):
        return True if args.keepgoing else False

    return True

def uninitialized(args):
    if 'jail' not in args: args.jail = False
    if 'initproc' not in args: args.initproc = False
    if 'root' not in args: args.root = None
    if 'scratch' not in args: args.scratch = None
    if 'chroot' not in args: args.chroot = None
    if 'outdir' not in args: args.outdir = None
    if 'redirect' not in args: args.redirect = None
    if 'timeout' not in args: args.timeout = 1

def do_all_tests(args, tests):
    uninitialized(args)
    for t, n in tests:
        print('=== TEST: %s' % t)
        if not do_one_test(args, t, n):
            break
