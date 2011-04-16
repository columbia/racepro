#!/usr/bin/python

import os
import sys
import time
import shutil
import signal
import logging
import argparse
import datetime
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

def _wait(p, timeout=None):
    if not timeout:
        r = p.wait()
    else:
        time.sleep(float(timeout))
        r = p.poll()
        if r == None:
            try:
                _sudo('kill -TERM %d' % p.pid)
            except OSError:
                pass
        p.wait()
    return r if r else 0

def _record(args, logfile=None, opts=''):
    if not logfile:
        logfile = args.path + '.log'
    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:
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
        p = exe.execute_raw(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
        ret = _wait(p, args.parallel)

        if args._post:
            logging.info('    clean-up after recording...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dummy, stdout=args.redirect)

        if ret != 0:
            logging.error('failed recording')
            return False

        return True

def _replay(args, logfile=None, opts=''):
    if not logfile:
        logfile = args.path + '.log'
    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:
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

        if args.jailed and args.archive:
            logdir = args.path + '.rw'
            _sudo('rm -rf %s' % logdir)
            _sudo('cp -ax %s %s' % (exe.scratch, logdir))

        return True if ret == 0 else False

def _replay2(args, logfile, verbose, opts=''):
    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:
        if args._pre:
            logging.info('    clean-up before replaying...')
            cmd = args._pre \
                if os.path.isabs(args._pre) \
                else './' + args._pre
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r != 0:
                logging.error('failed pre-script (exit %d)' % r)
                print(verbose + 'bad exit code from pre-script: %d' % r)
                return False

        logging.info('    replaying ...')
        cmd = args.replay + ' %s %s' % (opts, logfile)
        p = exe.execute_raw(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)

        if args.parallel:
            time.sleep(float(args.parallel))
            ret = p.poll()
        else:
            ret = p.wait()

        if ret is not None:
            if ret == 35:
                print(verbose + 'replay deadlock')
            elif ret > 0:
                print(verbose + 'replay failure (exit %d)' % ret)
            else:
                print(verbose + 'replay completed')

        # if non-parallel and ret==0, or parallel and ret==None:
        if args._test and (ret == 0 or (args.parallel and ret == None)):
            logging.info('    running test script...')
            cmd = args._test \
                if os.path.isabs(args._test) \
                else './' + args._test
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r == 2 or r == 255:
                print(verbose + 'BUG REPRODUCED')
                ret = 0
            elif r != 0:
                print(verbose + 'bad exit code from test-script: %d' % r)
                ret = r
            else:
                print(verbose + 'BUG not triggered')
                ret = 0
        elif ret == 0:
            print(verbose + 'BUG replayed but not tested')

        # if parallel, then terminate the replay init
        if args.parallel:
            # process may be gone by now ?
            try:
                p.kill()
            except OSError:
                pass
            p.wait()

        if args._post:
            logging.info('    clean-up after replaying...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dummy, stdout=args.redirect)
            if r != 0:
                logging.error('failed post-script (exit %d)' % r)
                print(verbose + 'bad exit code from post-script: %d' % r)

        if args.jailed and args.archive:
            logdir = logfile.replace('.log', '.rw')
            _sudo('rm -rf %s' % logdir)
            _sudo('cp -ax %s %s' % (exe.scratch, logdir))

    return True if ret == 0 else False

def _findraces(args, opts):
    cmd = args.racepro + '%s show-races -i %s -o %s' % \
        (opts, args.path + '.log', args.path)
    ret = _sudo(cmd)
    if ret != 0:
        logging.error('failed to generate races')
        return False
    return True

def _testlist(args, races):

    for n in races:
        t_start = datetime.datetime.now()
        logfile = '%s.%d.log' % (args.path, n)
        if not os.access(logfile, os.R_OK):
            logging.error('failed to test races: cannot access %s' % logfile)
            break
        v = 'RACE %d: ' % n
        o = '-c %d' % args.timeout
        ret = _replay2(args, logfile, v, opts=o)
        t_end = datetime.datetime.now()
        dt = t_end - t_start
        logging.info('    time:  %.2f' %
                     (dt.seconds + dt.microseconds / 1000000.0))
        if not ret and not args.keepgoing:
            return False
    return True

def _testraces(args):
    ret = _testlist(args, count(1))
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
    if args.initproc: args.record += ' -i'
    if args.netns: args.record += ' -n'

    args.replay = 'replay -l 15'
    args.racepro = 'racepro'

    logging.info('Processing test: %s' % (t_name))

    args.pdir = args.outdir + '/' + t_name
    args.path = args.outdir + '/' + t_name + '/out'

    def def_script_name(path):
        return path if os.access(path, os.R_OK | os.X_OK) else None

    args._run = args.run if 'run' in args else '%s' % t_exec
    args._test = args.test \
        if 'test' in args else def_script_name('%s.test' % t_name)
    args._pre = args.pre \
        if 'pre' in args else def_script_name('%s.pre' % t_name)
    args._post = args.post \
        if 'post' in args else def_script_name('%s.post' % t_name)

    if args._test and not os.access(args._test, os.X_OK):
        logging.error('%s: test script request but not found' % args._test)
        return False
    if args._pre and not os.access(args._pre, os.X_OK):
        logging.error('%s: pre script request but not found' % args._pre)
        return False
    if args._post and not os.access(args._post, os.X_OK):
        logging.error('%s: post script request but not found' % args._post)
        return False

    opts = ''
    if args.debug: opts += ' -d'
    if args.verbose: opts += ' -v'

    logging.info('  output in directory %s' % args.pdir)

    if not args.skip_record:
        if os.access(args.pdir, os.R_OK):
            _sudo('rm -rf %s' % args.pdir)
    _sudo('mkdir -p %s' % args.pdir)

    if args.quiet:
        args.redirect = open(args.path + '.out', 'w')
    else:
        args.redirect = None

    t_start = datetime.datetime.now()

    if not args.skip_record:
        logging.info('  recording original exceution (twice)')
        if not _record(args):
            return True if args.keepgoing else False
        if not _record(args):
            return True if args.keepgoing else False

        t_replay = datetime.datetime.now()

        logging.info('  replaying original execution')
        if not _replay(args):
            return True if args.keepgoing else False

    else:
        t_replay = t_start

    t_record = datetime.datetime.now()

    if not args.skip_findrace:
        logging.info('  generating the races')
        if not _findraces(args, opts):
            return True if args.keepgoing else False

    t_findrace = datetime.datetime.now()

    if not args.skip_testrace:
        logging.info('  testing the races (auto)')
        if not _testraces(args):
            return True if args.keepgoing else False

    t_stop = datetime.datetime.now()

    if args.race_list:
        logging.info('  testing the races (list)')
        if not _testlist(args, map(int, args.race_list.split(':'))):
            return True if args.keepgoing else False

    if args.race_file:
        logging.info('  testing the races (list)')
        with open(args.race_file) as file:
            for line in file:
                if not _testlist(args, map(int, line.split(':'))):
                    return True if args.keepgoing else False

    dt_replay = t_replay - t_start
    dt_record = t_record - t_replay
    dt_findrace = t_findrace - t_record
    dt_testrace = t_stop - t_findrace
    dt_total = t_stop - t_start
    logging.info('total time:     %.2f' %
                 (dt_total.seconds + dt_total.microseconds / 1000000.0))
    logging.info('total record:   %.2f' %
                 (dt_record.seconds + dt_record.microseconds / 1000000.0))
    logging.info('total replay:   %.2f' %
                 (dt_replay.seconds + dt_replay.microseconds / 1000000.0))
    logging.info('total findrace: %.2f' %
                 (dt_findrace.seconds + dt_findrace.microseconds / 1000000.0))
    logging.info('total testrace: %.2f' %
                 (dt_testrace.seconds + dt_testrace.microseconds / 1000000.0))

    return True

def uninitialized(args):
    if 'timeout' not in args: args.timeout = 1
    if 'jailed' not in args: args.jailed = False
    if 'initproc' not in args: args.initproc = False
    if 'parallel' not in args: args.parallel = None
    if 'archive' not in args: args.archive = False
    if 'netns' not in args: args.netns = False
    if 'outdir' not in args: args.outdir = None
    if 'redirect' not in args: args.redirect = None
    if 'root' not in args: args.root = None
    if 'scratch' not in args: args.scratch = None
    if 'chroot' not in args: args.chroot = None
    if 'race_file' not in args: args.race_file = None
    if 'race_list' not in args: args.race_list = None
    if 'skip_record' not in args: args.skip_record = None
    if 'skip_findrace' not in args: args.skip_findrace = None
    if 'skip_testrace' not in args: args.skip_testrace = None

def do_all_tests(args, tests):
    uninitialized(args)
    for t_name, t_exec in tests:
        print('=== TEST: %s' % t_name)
        if not do_one_test(args, t_name, t_exec):
            break
