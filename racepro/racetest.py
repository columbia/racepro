#!/usr/bin/python

import re
import os
import sys
import logging
import datetime
import itertools
import traceback
import pdb

import scribewrap
import eventswrap
import execgraph
import execute
import races

##############################################################################

def _handle_toctou(exe, string):
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

def on_bookmark_toctou(exe, logfile, scribe, id, npr):
    try:
        log = re.sub('\.log$', '.toctou', logfile.name)
        for line in open(log, 'r').readlines():
            _handle_toctou(exe, line)
            scribe.stop()
    except:
        traceback.print_exc(file=sys.stdout)

def replay_test_script(exe, args):
    if args.toctou:
        logging.info('    running generic toctou script...')
    else:
        logging.info('    running specific test script...')

    try:
        scribewrap.def_test_script(exe, args)
    except execute.ExecuteError as e:
        if e.ret != 2:
            print('unexpected exit code %d' % e.ret)
        return True
    else:
        return False

def _testlist(args, races):
    if args.toctou:
        on_bookmark = on_bookmark_toctou
    else:
        on_bookmark = None

    for n in races:
        t_start = datetime.datetime.now()
        logfile = '%s.%d.log' % (args.path, n)
        if not os.access(logfile, os.R_OK):
            break
        verbose = 'RACE %d: ' % n
        ret = scribewrap.scribe_replay(args, logfile, verbose,
                                       test_replay=replay_test_script,
                                       on_bookmark=on_bookmark)
        t_end = datetime.datetime.now()
        dt = t_end - t_start
        logging.info('    time:  %.2f' %
                     (dt.seconds + dt.microseconds / 1000000.0))
        if not ret and not args.keepgoing:
            return False
    return True

def _testraces(args):
    _testlist(args, itertools.count(1))
    return True

def _findraces(args, opts):
    args.logfile = args.path + '.log'

    events = eventswrap.load_events(args.logfile)
    graph = execgraph.ExecutionGraph(events)
    if args.toctou:
        races.find_show_toctou(graph, args)
    else:
        races.find_show_races(graph, args)
    return True

def do_one_test(args, t_name, t_exec):
    if args.chroot and not os.access(args.chroot, os.R_OK | os.X_OK):
        os.mkdir(args.chroot)

    if args.scratch and os.access(args.scratch, os.F_OK):
        cmd = 'rm -rf %s' % args.scratch
        execute.sudo(cmd.split())
        os.mkdir(args.scratch)

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

    logging.debug('%s %s' % (t_name, t_exec))

    if args._test and not os.access(args._test, os.X_OK):
        logging.error('%s: test script request but not found' % args._test)
        return False
    if args._pre and not os.access(args._pre, os.X_OK):
        logging.error('%s: pre script request but not found' % args._pre)
        return False
    if args._post and not os.access(args._post, os.X_OK):
        logging.error('%s: post script request but not found' % args._post)
        return False

    if args.toctou:
        args._test = 'toctou test'

    opts = ''
    if args.debug: opts += ' -d'
    if args.verbose: opts += ' -v'

    logging.info('  output in directory %s' % args.pdir)

    if not args.skip_record:
        if os.access(args.pdir, os.R_OK):
            cmd = 'rm -rf %s' % args.pdir
            execute.sudo(cmd.split())
    cmd = 'mkdir -p %s' % args.pdir
    execute.sudo(cmd.split())

    if args.quiet:
        args.redirect = open(args.path + '.out', 'w')
    else:
        args.redirect = None

    t_start = datetime.datetime.now()

    if not args.skip_record:
        logging.info('  recording original exceution (twice)')
        if not scribewrap.scribe_record(args):
            return True if args.keepgoing else False
        if not scribewrap.scribe_record(args):
            return True if args.keepgoing else False

        t_replay = datetime.datetime.now()

        # If args.max_runtimes was enabled, then recording may have stopped
        # an "external" script; We expect replay to also stop similarly, so
        # we don't need to temporarilty turn off args.max_runtime.
        logging.info('  replaying original execution')
        if not scribewrap.scribe_replay(args):
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
    if 'count' not in args: args.count = 5000
    if 'keepgoing' not in args: args.keepgoing = False
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
    if os.geteuid() != 0:
        print('You must be root to use racetest')
        exit(1)

    uninitialized(args)

    for t_name, t_exec in tests:
        print('=== TEST: %s' % t_name)
        if not do_one_test(args, t_name, t_exec):
            break
