#!/usr/bin/python

import re
import os
import sys
import logging
import datetime
import itertools
import traceback
import pdb
import time

import scribewrap
import eventswrap
import execgraph
import execute
import racecore
import session
import toctou
from helpers import *

##############################################################################
def replay_test_script(exe, args):
    logging.info('    running test script...')

    def toctou_handle_test(exe):
        pid = os.fork()
        if pid == 0:
            result = False

            exe.prepare()
            logging.info('    running generic test script...')

            for line in open('/.TEST', 'r').readlines():
                args = line.split()
                if toctou.test_toctou(args[1], args[2:]):
                    result = True

            if result:
                os._exit(2)
            else:
                os._exit(0)
        else:
            return os.waitpid(pid, 0)[1] >> 8

    if args.toctou:
        if toctou_handle_test(exe) == 2:
            return True

    try:
        scribewrap.def_test_script(exe, args)
    except execute.ExecuteError as e:
        if e.ret != 2:
            print('unexpected exit code %d' % e.ret)
        return True
    else:
        return False

def _testlist(args, races):

    def toctou_handle_attack(exe, string):
        pid = os.fork()
        if pid == 0:
            exe.prepare()
            args = string.split()
            assert args[0] == 'attack'
            toctou.attack_toctou(args[1], args[2:])
            os._exit(0)
        else:
            os.waitpid(pid, 0)

    def toctou_bookmark_cb(exe, logfile, scribe, id, npr):
        logging.info('    running generic attack script...')
        try:
            log = re.sub('\.log$', '.toctou', logfile)
            for line in open(log, 'r').readlines():
                toctou_handle_attack(exe, line)
            scribe.stop()
        except:
            traceback.print_exc(file=sys.stdout)
        return False

    if args.toctou:
        bookmark_cb = scribewrap.Callback(toctou_bookmark_cb)
    else:
        bookmark_cb = None

    for n in races:
        t_start = datetime.datetime.now()
        logfile = '%s.%d.log' % (args.path, n)
        if not os.access(logfile, os.R_OK):
            break
        verbose = 'RACE %d: ' % n
        ret = scribewrap.scribe_replay(args, logfile, verbose,
                                       test_replay=replay_test_script,
                                       bookmark_cb=bookmark_cb)
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

    t_start = datetime.datetime.now()

    events = eventswrap.load_events(args.logfile)
    graph = execgraph.ExecutionGraph(events)

    t_graph = datetime.datetime.now()

    if not args.skip_predetect:
        if args.toctou:
            bookmarks_list = racecore.BookmarksForToctou
        else:
            bookmarks_list = racecore.BookmarksForResources

        logging.info('  replaying execution for pre-detect')
        racecore.instrumented_replay(graph, args, bookmarks_list)

    t_instrumented = datetime.datetime.now()

    args.t_graph = t_graph - t_start
    args.t_instrumented = t_instrumented - t_graph

    if args.toctou:
        racecore.find_show_toctou(graph, args)
    else:
        racecore.find_show_races(graph, args)

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

    if args._pre and not (args.skip_record and args.skip_testrace):
        logging.info('  prepare pre-script')
        if not scribewrap.prepare_pre_script(args):
            return True if args.keepgoing else False

        t_prepare = args.t_prepare
    else:
        t_prepare = datetime.timedelta(0)

    if not args.skip_normal and not (args.skip_record and args.skip_testrace):
        logging.info('  normal run without scribe')
        if not scribewrap.do_no_scribe(args):
            return True if args.keepgoing else False

        t_noscribe = args.t_run
        t_noscribe_extra = args.t_isolate + args.t_post_run
    else:
        t_noscribe = t_noscribe_extra = datetime.timedelta(0)

    if not args.skip_record:
        logging.info('  recording original exceution (twice)')
        if not scribewrap.scribe_record(args):
            return True if args.keepgoing else False
        if not args.jailed and not scribewrap.scribe_record(args):
            return True if args.keepgoing else False

        t_record = args.t_record
        t_record_extra = args.t_isolate + args.t_post_record

        # If args.max_runtimes was enabled, then recording may have stopped
        # an "external" script; We expect replay to also stop similarly, so
        # we don't need to temporarilty turn off args.max_runtime.
        logging.info('  replaying original execution')
        max_runtime = args.max_runtime
        args.max_runtime = 0
        if not scribewrap.scribe_replay(args):
            return True if args.keepgoing else False
        args.max_runtime = max_runtime

        t_replay = args.t_replay
        t_replay_extra = args.t_isolate + args.t_post_replay

    else:
        t_record = t_record_extra = datetime.timedelta(0)
        t_replay = t_replay_extra = datetime.timedelta(0)

    if not args.skip_findrace:
        logging.info('  generating the races')
        if not _findraces(args, opts):
            return True if args.keepgoing else False

        t_graph = args.t_graph
        t_instrumented = args.t_instrumented
        t_detect = args.t_detect
        t_detect_noopt = args.t_detect_noopt
        t_outputrace = args.t_outputrace
    else:
        t_graph = t_instrumented = t_detect = t_detect_noopt = \
                  t_outputrace = datetime.timedelta(0)

    t_findrace = t_graph + t_instrumented + t_detect + t_outputrace

    t_start_testrace = datetime.datetime.now()

    if not args.skip_testrace:
        logging.info('  testing the races (auto)')
        if not _testraces(args):
            return True if args.keepgoing else False

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

    t_stop_testrace = datetime.datetime.now()
    t_testrace = t_stop_testrace - t_start_testrace

    t_total = t_noscribe + t_noscribe_extra + t_record + t_record_extra + \
              t_replay + t_replay_extra + t_findrace + t_testrace

    logging.info('prepare:        %.4f' %
                 (t_prepare.seconds + t_prepare.microseconds / 1000000.0)) 
    logging.info('noscribe:        %.4f' %
                 (t_noscribe.seconds + t_noscribe.microseconds / 1000000.0)) 
    logging.info('noscribe extra:  %.4f' %
                 (t_noscribe_extra.seconds + t_noscribe_extra.microseconds / 1000000.0))
    logging.info('record:          %.4f' %
                 (t_record.seconds + t_record.microseconds / 1000000.0))
    logging.info('record extra:    %.4f' %
                 (t_record_extra.seconds + t_record_extra.microseconds / 1000000.0))
    logging.info('replay:          %.4f' %
                 (t_replay.seconds + t_replay.microseconds / 1000000.0))
    logging.info('replay extra:    %.4f' %
                 (t_replay_extra.seconds + t_replay_extra.microseconds / 1000000.0))
    logging.info('instrumented:    %.4f' %
                 (t_instrumented.seconds + t_instrumented.microseconds / 1000000.0))
    logging.info('detect:          %.4f' %
                 (t_detect.seconds + t_detect.microseconds / 1000000.0))
    logging.info('detect (no opt): %.4f' %
                 (t_detect_noopt.seconds + t_detect_noopt.microseconds / 1000000.0))
    logging.info('outputrace:      %.4f' %
                 (t_outputrace.seconds + t_outputrace.microseconds / 1000000.0)) 
    logging.info('findrace:        %.4f' %
                 (t_findrace.seconds + t_findrace.microseconds / 1000000.0))
    logging.info('testrace:        %.4f' %
                 (t_testrace.seconds + t_testrace.microseconds / 1000000.0))
    logging.info('total:           %.4f' %
                 (t_total.seconds + t_total.microseconds / 1000000.0)) 

    return True

def uninitialized(args):
    if 'timeout' not in args: args.timeout = 0
    if 'max_races' not in args: args.max_races = None
    if 'ignore_path' not in args: args.ignore_path = None
    if 'check_nr' not in args: args.check_nr = None
    if 'jailed' not in args: args.jailed = False
    if 'initproc' not in args: args.initproc = False
    if 'max_runtime' not in args: args.max_runtime = None
    if 'archive' not in args: args.archive = False
    if 'netns' not in args: args.netns = False
    if 'keepgoing' not in args: args.keepgoing = False
    if 'outdir' not in args: args.outdir = None
    if 'redirect' not in args: args.redirect = None
    if 'root' not in args: args.root = None
    if 'scratch' not in args: args.scratch = None
    if 'chroot' not in args: args.chroot = None
    if 'race_file' not in args: args.race_file = None
    if 'race_list' not in args: args.race_list = None
    if 'skip_normal' not in args: args.skip_normal = None
    if 'skip_record' not in args: args.skip_record = None
    if 'skip_predetect' not in args: args.skip_predetect = None
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
