#!/usr/bin/python

import os
import signal
import logging
import subprocess
import errno
import time
import pdb
import datetime

import execute
import scribe

_dev_null = open('/dev/null', 'r')

# helpers for execution

def exec_piped(cmd, redirect=None):
    """Run @cmd such that it doesn't use pty/tty"""
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

# scribe wrapper material

class Callback:
    def __init__(self, function, **private):
        self._function = function
        self._private = private

    def __call__(self, **kargs):
        newkargs = dict(self._private.items() + kargs.items())
        return self._function(**newkargs)

def _do_scribe_exec(cmd, logfile, exe, stdout, flags,
                    deadlock=None, backtrace=50,
                    record=False, replay=False,
                    bookmark_cb=None):

    context = None
    exe.pids = dict()

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
            if bookmark_cb:
                resume = bookmark_cb(scribe=self, id=id, npr=npr)
            else:
                resume = True
            if resume:
                self.resume()

        def on_attach(self, real_pid, scribe_pid):
            exe.pids[scribe_pid] = real_pid

    context = RaceproContext(logfile,
                             backtrace_len=50,
                             backtrace_num_last_events=backtrace)

    context.add_init_loader(lambda argv, envp: exe.prepare())
    pinit = scribe.Popen(context, cmd,
                         record=record, replay=replay, flags=flags,
                         stdin=_dev_null, stdout=subprocess.PIPE)
    pcat = subprocess.Popen(['/bin/cat'],
                            stdin=pinit.stdout,
                            stdout=stdout,
                            stderr=subprocess.STDOUT)

    return (context, pinit)

def _do_scribe_wait(context, p, timeout=None, kill=False):
    logging.info("timeout: %s, kill: %s" % (timeout, kill))
    try:
        if not timeout:
            assert not kill
            logging.info("context.wait() [1]")            
            context.wait()
            return p.wait()

        time.sleep(float(timeout))

        r = p.poll()
        if r is not None:
            logging.info("context.wait() [2]")
            context.wait()
            return p.wait()

        if kill:
            try:
                p.kill()
            except OSError:
                pass
            logging.info("context.wait() [3]")
            context.wait()
            return p.wait()

        return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0, 0)

def _do_scribe_script(exe, script, redirect, nsexec = False, 
                      initproc = False, netns = False):
    if script:
        cmd = os.path.join(os.getcwd(), script)

        if nsexec:
            nscmd = ['nsexec', '-c', '-p']
            if not initproc:
                nscmd += ['-I']
            if netns:
                nscmd += ['-n']
        else:
            nscmd = []

        ret = exe.execute(nscmd + cmd.split(), notty=True,
                          stdin=_dev_null, stdout=redirect)
        if ret:
            raise execute.ExecuteError(script, ret)

def def_pre_script(exe, args):
    _do_scribe_script(exe, args._pre, args.redirect)

def def_post_script(exe, args):
    _do_scribe_script(exe, args._post, args.redirect)

def def_test_script(exe, args):
    _do_scribe_script(exe, args._test, args.redirect)


def do_no_scribe(args, pre_run=def_pre_script, post_run=def_post_script):

    t_start = datetime.datetime.now()

    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:

        t_isolate = datetime.datetime.now()

        if pre_run:
            logging.info('    running pre-run callback...')
            pre_run(exe, args)

        t_pre_run = datetime.datetime.now()

        logging.info('    running ...')
        if args.max_runtime:
            if os.fork() == 0:
                _do_scribe_script(exe, args._run, args.redirect, nsexec = True, 
                                  initproc = args.initproc, netns = args.netns)
                os._exit(0)
            else: 
                time.sleep(float(args.max_runtime))
        else:
            _do_scribe_script(exe, args._run, args.redirect, 
                                             initproc = args.initproc, 
                                             netns = args.netns)

        t_run = datetime.datetime.now()

        if args._post:
            logging.info('    running post-run callback...')
            post_run(exe, args)

        t_post_run = datetime.datetime.now()

        if args.max_runtime:
            os.wait()

    t_end = datetime.datetime.now()

    args.t_isolate = t_isolate - t_start
    args.t_pre_run = t_pre_run - t_isolate
    args.t_run = t_run - t_pre_run
    args.t_post_run = t_post_run - t_run
    args.t_unisolate = t_end - t_post_run

    return True

def scribe_record(args, logfile=None,
                  pre_record=def_pre_script,
                  post_record=def_post_script):
    if not logfile:
        logfile = args.path + '.log'

    t_start = datetime.datetime.now()

    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:

        t_isolate = datetime.datetime.now()

        if pre_record:
            logging.info('    running pre-record callback...')
            pre_record(exe, args)

        t_pre_record = datetime.datetime.now()

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
                context, pinit = _do_scribe_exec(
                        cmd, file, exe, args.redirect, flags, record=True)

                _do_scribe_wait(context, pinit, args.max_runtime,
                                kill=not not args.max_runtime)
            except Exception as e:
                logging.error('failed recording: %s' % e)
                success = False
            else:
                logging.info('record completed')
                success = True

        t_record = datetime.datetime.now()

        if post_record:
            logging.info('    running post-record callback...')
            post_record(exe, args)

        t_post_record = datetime.datetime.now()

    t_end = datetime.datetime.now()

    args.t_isolate = t_isolate - t_start
    args.t_pre_record = t_pre_record - t_isolate
    args.t_record = t_record - t_pre_record
    args.t_post_record = t_post_record - t_record
    args.t_unisolate = t_end - t_post_record
    
    return success

def scribe_replay(args, logfile=None, verbose='', bookmark_cb=None,
                  pre_replay=def_pre_script,
                  post_replay=def_post_script,
                  test_replay=None):
    if not logfile:
        logfile = args.path + '.log'

    t_start = datetime.datetime.now()

    with execute.open(jailed=args.jailed, chroot=args.chroot, root=args.root,
                      scratch=args.scratch, persist=args.pdir) as exe:
        if bookmark_cb:
            bookmark_cb = Callback(bookmark_cb, exe=exe, logfile=logfile)

        t_isolate = datetime.datetime.now()

        if pre_replay:
            logging.info('    running pre-replay callback...')
            pre_replay(exe, args)

        t_pre_replay = datetime.datetime.now()

        logging.info('    replaying ...')
        with open(logfile, 'r') as file:
            pinit = None
            ret = None
            try:
                context, pinit =  _do_scribe_exec(
                        None, file, exe, args.redirect, 0, deadlock=1,
                        replay=True, bookmark_cb=bookmark_cb)
                ret = _do_scribe_wait(context, pinit, args.max_runtime,
                                      not not args.max_runtime)
            except scribe.DeadlockError as derr:
                logging.info(str(derr))
                if verbose:
                    print(verbose + 'replay deadlock')
                success = False
            except scribe.DivergeError as derr:
                logging.info(str(derr))
                if verbose:
                    print(verbose + 'replay diverge (%d)' % derr.err)
                success = False
            except Exception as e:
                logging.error('failed replaying: %s' % e)
                success = False
            else:
                if args.max_runtime:
                    if ret is None:
                        print('replay in-transit')
                        success = True
                    else:
                        print(verbose + 'replay died early (%d)' % ret)
                else:
                    logging.info('replay completed')
                success = True

        if test_replay and success:
            logging.info('    running test-replay callback...')
            if test_replay(exe, args):
                print(verbose + 'BUG REPRODUCED')
            else:
                print(verbose + 'BUG not triggered')
        elif success and verbose:
            print(verbose + 'BUG replayed but not tested')

        if args.max_runtime and success:
            _do_scribe_wait(context, pinit, 0.01, True)

        t_replay = datetime.datetime.now()

        if post_replay:
            logging.info('    running post-replay callback...')
            post_replay(exe, args)

        if args.jailed and args.archive:
            logdir = args.path + '.rw'
            exec_piped('rm -rf %s' % logdir)
            exec_piped('cp -ax %s %s' % (exe.scratch, logdir))

        t_post_replay = datetime.datetime.now()

    t_end = datetime.datetime.now()

    args.t_isolate = t_isolate - t_start
    args.t_pre_replay = t_pre_replay - t_isolate
    args.t_replay = t_replay - t_pre_replay
    args.t_post_replay = t_post_replay - t_replay
    args.t_unisolate = t_end - t_post_replay

    return success
