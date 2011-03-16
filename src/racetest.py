#!/usr/bin/python

import os
import sys
import shutil
import logging
import argparse
import subprocess
import pdb

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

def _record(args):
    with execute.open(root=args.root, jailed=args.jailed,
                      chroot=args.chroot, scratch=args.scratch,
                      persist=args.pdir) as exe:
        if 'pre' in args and args.pre:
            logging.info('    clean-up before recording...')
            cmd = args.pre if os.path.isabs(args.pre) else './' + args.pre
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect,)

        logging.info('    recording ...')
        cmd = args.run if os.path.isabs(args.run) else './' + args.run
        cmd = args.record + ' -o %s %s' % (args.path + '.log', cmd)
        ret = exe.execute(cmd.split(), notty=True,
                          stdin=_dummy, stdout=args.redirect)

        if 'post' in args and args.post:
            logging.info('    clean-up after recording...')
            cmd = args.post if os.path.isabs(args.post) else './' + args.post
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect)

        if ret != 0:
            logging.error('failed 1st recording')
            return False

        return True

def _replay(args):
    with execute.open(root=args.root, jailed=args.jailed,
                      chroot=args.chroot, scratch=args.scratch,
                      persist=args.pdir) as exe:
        if 'pre' in args and args.pre:
            logging.info('    clean-up before replaying...')
            cmd = args.pre if os.path.isabs(args.pre) else './' + args.pre
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect)

        logging.info('    replaying ...')
        cmd = args.replay + ' %s' % (args.path + '.log')
        ret = exe.execute(cmd.split(), notty=True,
                          stdin=_dummy, stdout=args.redirect)

        if 'post' in args and args.post:
            logging.info('    clean-up after replaying...')
            cmd = args.post if os.path.isabs(args.post) else './' + args.post
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect)

            if ret != 0:
                logging.error('failed original replay')
                return False

        return True

def _findraces(args, opts):
    cmd = args.racepro + '%s show-races -i %s -o %s' % \
        (opts, args.path + '.log', args.path)
    ret = _sudo(cmd)
    if ret != 0:
        logging.error('failed to generate races')
        return False
    return True

def _testraces(args, opts1, opts2):
    with execute.open(root=args.root, jailed=args.jailed,
                      chroot=args.chroot, scratch=args.scratch,
                      persist=args.pdir) as exe:
        exitiffail = '' if args.keepgoing else '--exit-on-failed-replay'
        cmd = args.racepro + ' %s test-races -i %s -o %s %s %s' % \
            (opts1, args.path + '.log', args.path, opts2, exitiffail)

        ret = exe.execute(cmd.split(), notty=True,
                           stdin=_dummy, stdout=args.redirect)
    if ret != 0:
        logging.error('failed to test the races (exit %d)' % ret)
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
        args.run = '%s' % t_exec
    if 'test' not in args:
        args.test = '%s.test' % t_name
    if 'pre' not in args:
        args.pre = '%s.pre' % t_name
    if args.pre and not os.access(args.pre, os.R_OK | os.X_OK):
        args.pre = None
    if 'post' not in args:
        args.post = '%s.post' % t_name
    if args.post and not os.access(args.post, os.R_OK | os.X_OK):
        args.post = None

    opts1 = ''
    if args.debug: opts1 += ' -d'
    if args.verbose: opts1 += ' -v'

    opts2 = ''
    if args.pre: opts2 += ' --script-pre=./%s' % args.pre
    if args.test: opts2 = ' --script-test=./%s' % args.test
    if args.post: opts2 = ' --script-post=./%s' % args.post

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
    if not _findraces(args, opts1):
        return True if args.keepgoing else False

    logging.info('  testing the races')
    if not _testraces(args, opts1, opts2):
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
    if 'save' not in args: args.save = None

def do_all_tests(args, tests):
    uninitialized(args)
    for t, n in tests:
        print('=== TEST: %s' % t)
        if not do_one_test(args, t, n):
            break
