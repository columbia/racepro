#!/usr/bin/python

import re
import os
import sys
import time
import shutil
import signal
import logging
import argparse
import datetime
import subprocess
import errno
import pdb
import traceback

from itertools import *

import execute
import scribe
import races

_dev_null = open('/dev/null', 'r')

def _exec(cmd, redirect=None):
    p1 = subprocess.Popen(cmd.split(),
                          stdin=_dev_null,
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

def _handle_toctou(string, id, exe):
    pid = os.fork()
    if pid == 0:
        try:
            exe.prepare()
            args = string.split()
            assert args[0] == 'attack'
            races.attack_toctou(args[1], args[2:])
        except:
            pass
        os._exit(0)
    else:
        os.waitpid(pid, 0)

def _do_scribe(cmd, logfile, exe, stdout, flags,
               deadlock=None, backtrace=2, toctou=False,
               record=False, replay=False):
    context = None
    def do_check_deadlock(signum, stack):
        try:
            context.check_deadlock()
        except OSError as e:
            if e.errno != errno.EPERM:
                logging.error("Cannot check for deadlock (%s)" % str(e))
    if deadlock:
        signal.signal(signal.SIGALRM, do_check_deadlock)
        signal.setitimer(signal.ITIMER_REAL, deadlock, deadlock)

    class RaceproContext(scribe.Context):
        def on_bookmark(self, id, npr):
            if toctou:
                try:
                    toctou_log_path = re.sub('\.log$', '.toctou', logfile.name)
                    toctou_lines = open(toctou_log_path, 'r').readlines()
                    for toctou_line in toctou_lines:
                        _handle_toctou(toctou_line, id, exe)
                    self.stop()
                except:
                    traceback.print_exc(file=sys.stdout)

            else:
                self.resume()

    context = RaceproContext(logfile,
                             backtrace_len = 2,
                             backtrace_num_last_events = backtrace)

    context.add_init_loader(lambda argv, envp: exe.prepare())
    pinit = scribe.Popen(context, cmd,
                         record=record, replay=replay, flags=flags,
                         stdin=_dev_null, stdout=subprocess.PIPE)
    pcat = subprocess.Popen(['/bin/cat'],
                            stdin=pinit.stdout,
                            stdout=stdout,
                            stderr=subprocess.STDOUT)
    context.wait()

    if deadlock:
        signal.setitimer(signal.ITIMER_REAL, 0, 0)

    return pinit

def _do_wait(p, timeout=None, kill=False):
    if not timeout:
        assert not kill
        return p.wait()

    time.sleep(float(timeout))

    r = p.poll()
    if r is not None:
        return p.wait()

    if kill:
        try:
            p.kill()
        except OSError:
            pass
        return p.wait()

    return None

def _record(args, logfile=None):
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
                              stdin=_dev_null, stdout=args.redirect)

        logging.info('    recording ...')
        cmd = args._run if os.path.isabs(args._run) else './' + args._run

        flags = scribe.SCRIBE_SYSCALL_RET | \
                scribe.SCRIBE_SYSCALL_EXTRA | \
                scribe.SCRIBE_SIG_COOKIE | \
                scribe.SCRIBE_RES_EXTRA | \
                scribe.SCRIBE_DATA_EXTRA | \
                scribe.SCRIBE_DATA_STRING_ALWAYS | \
                scribe.SCRIBE_RES_ALWAYS | \
                scribe.SCRIBE_REGS

        if args.initproc:
            flags |= scribe.SCRIBE_CUSTOM_INIT
        if args.netns:
            flags |= scribe.SCRIBE_CLONE_NEWNET

        with open(logfile, 'w') as file:
            try:
                pinit = _do_scribe(cmd, file, exe,
                                   args.redirect, flags, record=True)
                _do_wait(pinit, args.max_runtime, kill=not not args.max_runtime)
            except Exception as e:
                logging.error('failed recording: %s' % e)
                success = False
            else:
                success = True

        if args._post:
            logging.info('    clean-up after recording...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            ret = exe.execute(cmd.split(), notty=True,
                              stdin=_dev_null, stdout=args.redirect)

        return success

def _replay(args, logfile=None):
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
                            stdin=_dev_null, stdout=args.redirect)
            if r != 0:
                logging.error('failed pre-script (exit %d)' % r)
                return False

        logging.info('    replaying ...')
        with open(logfile, 'r') as file:
            try:
                pinit =  _do_scribe(None, file, exe, args.redirect, 0,
                                    deadlock=1, replay=True)
                _do_wait(pinit)
            except Exception as e:
                logging.error('failed replaying: %s' % e)
                success = False
            else:
                success = True

        if args._post:
            logging.info('    clean-up after replaying...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dev_null, stdout=args.redirect)
            if r != 0:
                logging.error('failed post-script (exut %d)' % r)

        if args.jailed and args.archive:
            logdir = args.path + '.rw'
            _sudo('rm -rf %s' % logdir)
            _sudo('cp -ax %s %s' % (exe.scratch, logdir))

        return success

def _replay2(args, logfile, verbose):
    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:
        if args._pre:
            logging.info('    clean-up before replaying...')
            cmd = args._pre \
                if os.path.isabs(args._pre) \
                else './' + args._pre
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dev_null, stdout=args.redirect)
            if r != 0:
                logging.error('failed pre-script (exit %d)' % r)
                print(verbose + 'bad exit code from pre-script: %d' % r)
                return False

        logging.info('    replaying ...')
        with open(logfile, 'r') as file:
            pinit = None
            ret = None
            try:
                pinit = _do_scribe(None, file, exe, args.redirect, 0,
                                   deadlock=1, toctou=args.toctou, replay=True)
                ret = _do_wait(pinit, args.max_runtime)
            except scribe.DivergeError as derr:
                logging.info(str(derr))
                if derr.err == 35:
                    print(verbose + 'replay deadlock')
                else:
                    print(verbose + 'replay diverge (%d)' % derr.err)
                success = False
            except Exception as e:
                logging.error('replay failure: %s' % e)
                success = False
            else:
                if args.max_runtime:
                    if ret is None:
                        print('replay in-transit')
                        success = True
                    else:
                        print('replay died early (%d)' % ret)
                else:
                    print('replay completed')
                    success = True

        if args.toctou and success:
            logging.info('    running generic TOCTOU test script...')
            r = exe.execute(['toctou', 'test'], notty=True,
                            stdin=_dev_null, stdout=args.redirect)
            if r == 2 or r == 255:
                print(verbose + 'BUG REPRODUCED')
                ret = 0
                success = False

        if args._test and success:
            logging.info('    running test script...')
            cmd = args._test \
                if os.path.isabs(args._test) \
                else './' + args._test
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dev_null, stdout=args.redirect)


            if r == 2 or r == 255:
                print(verbose + 'BUG REPRODUCED')
                ret = 0
            elif r != 0:
                print(verbose + 'bad exit code from test-script: %d' % r)
                ret = r
            else:
                print(verbose + 'BUG not triggered')
                ret = 0
        elif success:
            print(verbose + 'BUG replayed but not tested')

        if args.max_runtime:
            _do_wait(pinit, 0, True)

        if args._post:
            logging.info('    clean-up after replaying...')
            cmd = args._post \
                if os.path.isabs(args._post) \
                else './' + args._post
            r = exe.execute(cmd.split(), notty=True,
                            stdin=_dev_null, stdout=args.redirect)
            if r != 0:
                logging.error('failed post-script (exit %d)' % r)
                print(verbose + 'bad exit code from post-script: %d' % r)

        if args.jailed and args.archive:
            logdir = logfile.replace('.log', '.rw')
            _sudo('rm -rf %s' % logdir)
            _sudo('cp -ax %s %s' % (exe.scratch, logdir))

    return success

def _findraces(args, opts):
    if args.toctou:
        cmd = args.racepro + '%s show-toctou -i %s -o %s' % \
            (opts, args.path + '.log', args.path)
    else:
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
            break
        v = 'RACE %d: ' % n
        o = '-c %d' % args.timeout
        ret = _replay2(args, logfile, v)
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
    if 'max_runtime' not in args: args.max_runtime = None
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
    if 'toctou' not in args: args.toctou = False

def do_all_tests(args, tests):
    uninitialized(args)

    for t_name, t_exec in tests:
        print('=== TEST: %s' % t_name)
        if not do_one_test(args, t_name, t_exec):
            break
